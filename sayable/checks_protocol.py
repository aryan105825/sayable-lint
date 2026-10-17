# @exports: run(url: str) -> list[Finding]  # always 9 findings PROTO-01..09, kind="spec", category="protocol", sorted by check_id
# @exports: parse_response_body(content_type: str, body: str) -> list[dict]  # JSON-RPC messages from an application/json or text/event-stream body; raises ValueError otherwise
# @exports: ProtocolCheckError(RuntimeError)  # raised when the server cannot be reached at all
# @exports: MIN_PROTOCOL: str = "2025-11-25"
# @imports: sayable/__init__.py:__version__
# @imports: sayable/schemas.py:Finding, Severity
# @env: (none)
# @schema: every POST sends Accept: application/json, text/event-stream
# @schema: PROTO-01 initialize ok and protocol >= 2025-11-25; PROTO-02 bad MCP-Protocol-Version -> 400; PROTO-03 initialized notification -> 202
# @schema: PROTO-04 bad Origin -> 403; PROTO-05 GET -> 405 or text/event-stream; PROTO-06 bogus Mcp-Session-Id -> 404 (pass if stateless)
# @schema: PROTO-07 tools/list entries schema-valid; PROTO-08 unknown method -> JSON-RPC -32601 and HTTP < 500; PROTO-09 401 advertises resource_metadata (pass if no auth)
from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Awaitable
from urllib.parse import urljoin, urlsplit

import httpx
from jsonschema import exceptions as js_exceptions
from jsonschema.validators import Draft202012Validator, validator_for

from sayable import __version__
from sayable.schemas import Finding, Severity

MIN_PROTOCOL = "2025-11-25"
ACCEPT = "application/json, text/event-stream"
BAD_PROTOCOL_VERSION = "1999-01-01"
BAD_ORIGIN = "https://sayable-bad-origin.invalid"
BOGUS_SESSION_ID = "sayable-bogus-session-id"
MAX_TOOL_PAGES = 50
MAX_REDIRECTS = 3
REDIRECT_STATUSES = (301, 302, 307, 308)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ProtocolCheckError(RuntimeError):
    """The server could not be reached, so no protocol check can run."""


@dataclass(frozen=True)
class _Resp:
    status: int
    headers: dict[str, str]
    messages: list[dict]
    parse_error: str | None
    body_text: str


def parse_response_body(content_type: str, body: str) -> list[dict]:
    media = content_type.split(";")[0].strip().lower()
    if media == "application/json":
        doc = json.loads(body)
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"JSON body contains a non-object message: {item!r}")
        return items
    if media == "text/event-stream":
        messages: list[dict] = []
        data_lines: list[str] = []
        lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for line in lines + [""]:
            if line == "":
                if data_lines:
                    payload = "\n".join(data_lines)
                    data_lines = []
                    if payload.strip():
                        doc = json.loads(payload)
                        if not isinstance(doc, dict):
                            raise ValueError(f"SSE data is not a JSON object: {payload!r}")
                        messages.append(doc)
            elif line.startswith("data:"):
                value = line[5:]
                if value.startswith(" "):
                    value = value[1:]
                data_lines.append(value)
        return messages
    raise ValueError(
        f"unsupported content-type {content_type!r}; expected application/json or text/event-stream"
    )


def _to_resp(r: httpx.Response) -> _Resp:
    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text
    messages: list[dict] = []
    parse_error: str | None = None
    if body.strip():
        try:
            messages = parse_response_body(headers.get("content-type", ""), body)
        except ValueError as exc:
            parse_error = f"{type(exc).__name__}: {exc}"
    return _Resp(r.status_code, headers, messages, parse_error, body)


async def _post(
    client: httpx.AsyncClient, url: str, payload: dict, headers: dict[str, str]
) -> _Resp:
    merged = {"Accept": ACCEPT, "Content-Type": "application/json"}
    merged.update(headers)
    r = await client.post(url, content=json.dumps(payload), headers=merged)
    return _to_resp(r)


def _rpc(method: str, rid: int, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}


def _reply(resp: _Resp, rid: int) -> dict | None:
    for message in resp.messages:
        if message.get("id") == rid and ("result" in message or "error" in message):
            return message
    return None


def _f(check_id: str, severity: Severity, message: str, **evidence: Any) -> Finding:
    return Finding(
        check_id=check_id,
        category="protocol",
        kind="spec",
        severity=severity,
        message=message,
        evidence=evidence,
    )


def _blocked(check_id: str) -> Finding:
    return _f(
        check_id,
        "fail",
        "Not testable because initialize did not succeed. Fix PROTO-01 first.",
    )


def _redirect_target(base: str, location: str | None) -> str | None:
    """Where a redirect points, only if it stays on the same scheme and host; otherwise None."""
    if not location:
        return None
    target = urljoin(base, location)
    b, t = urlsplit(base), urlsplit(target)
    if t.scheme not in ("http", "https") or (t.scheme, t.netloc) != (b.scheme, b.netloc):
        return None
    return target


async def _guard(check_id: str, check: Awaitable[Finding]) -> Finding:
    try:
        return await check
    except httpx.HTTPError as exc:
        return _f(
            check_id,
            "fail",
            f"Transport error while running {check_id}: {type(exc).__name__}: {exc}",
            error=f"{type(exc).__name__}: {exc}",
        )


def _negotiated_version(init: _Resp, rid: int) -> str | None:
    reply = _reply(init, rid)
    if init.status == 200 and reply is not None and isinstance(reply.get("result"), dict):
        version = reply["result"].get("protocolVersion")
        if isinstance(version, str):
            return version
    return None


def _proto01(init: _Resp, rid: int) -> tuple[Finding, str | None]:
    evidence: dict[str, Any] = {
        "http_status": init.status,
        "content_type": init.headers.get("content-type"),
        "parse_error": init.parse_error,
    }
    version = _negotiated_version(init, rid)
    if version is None:
        hint = ""
        if 300 <= init.status < 400:
            hint = " The server redirected; use the exact endpoint URL (often ending in /mcp)."
        return (
            _f(
                "PROTO-01",
                "fail",
                f"initialize did not return a result (HTTP {init.status}).{hint}",
                **evidence,
            ),
            None,
        )
    evidence["protocolVersion"] = version
    if not _DATE_RE.fullmatch(version) or version < MIN_PROTOCOL:
        return (
            _f(
                "PROTO-01",
                "fail",
                f"Server negotiated protocol {version!r}; {MIN_PROTOCOL} or later is required.",
                **evidence,
            ),
            version,
        )
    return _f("PROTO-01", "pass", f"initialize ok, protocol {version}.", **evidence), version


def _proto09(init: _Resp) -> Finding:
    if init.status == 401:
        challenge = init.headers.get("www-authenticate", "")
        if "resource_metadata" in challenge.lower():
            return _f(
                "PROTO-09",
                "pass",
                "401 response advertises OAuth protected-resource metadata.",
                www_authenticate=challenge,
            )
        return _f(
            "PROTO-09",
            "warn",
            "401 response does not include resource_metadata in WWW-Authenticate.",
            www_authenticate=challenge,
        )
    return _f(
        "PROTO-09",
        "pass",
        f"No authentication challenge observed (initialize returned HTTP {init.status}).",
        http_status=init.status,
    )


async def _check_initialized(client: httpx.AsyncClient, url: str, sess: dict[str, str]) -> Finding:
    r = await _post(
        client, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sess
    )
    if r.status == 202:
        return _f("PROTO-03", "pass", "notifications/initialized returned 202.", http_status=202)
    return _f(
        "PROTO-03",
        "fail",
        f"notifications/initialized returned HTTP {r.status}; the spec requires 202 Accepted.",
        http_status=r.status,
    )


async def _check_bad_version(
    client: httpx.AsyncClient, url: str, sess: dict[str, str], rid: int
) -> Finding:
    headers = dict(sess)
    headers["MCP-Protocol-Version"] = BAD_PROTOCOL_VERSION
    r = await _post(client, url, _rpc("tools/list", rid), headers)
    if r.status == 400:
        return _f("PROTO-02", "pass", "Invalid MCP-Protocol-Version header got 400.", http_status=400)
    return _f(
        "PROTO-02",
        "fail",
        f"Invalid MCP-Protocol-Version header got HTTP {r.status}; the spec requires 400.",
        http_status=r.status,
    )


async def _check_bad_origin(
    client: httpx.AsyncClient, url: str, sess: dict[str, str], rid: int
) -> Finding:
    headers = dict(sess)
    headers["Origin"] = BAD_ORIGIN
    r = await _post(client, url, _rpc("tools/list", rid), headers)
    if r.status == 403:
        return _f("PROTO-04", "pass", "Request with a foreign Origin got 403.", http_status=403)
    return _f(
        "PROTO-04",
        "fail",
        f"Request with a foreign Origin got HTTP {r.status}; servers must reject it with 403 "
        "(enable DNS-rebinding / Origin protection).",
        http_status=r.status,
    )


async def _check_get(client: httpx.AsyncClient, url: str, sess: dict[str, str]) -> Finding:
    headers = {"Accept": "text/event-stream"}
    headers.update(sess)
    async with client.stream("GET", url, headers=headers) as r:
        status = r.status_code
        content_type = r.headers.get("content-type", "")
    media = content_type.split(";")[0].strip().lower()
    if status == 405 or (status == 200 and media == "text/event-stream"):
        return _f(
            "PROTO-05",
            "pass",
            f"GET returned {status} ({media or 'no body'}), which the spec allows.",
            http_status=status,
            content_type=content_type,
        )
    return _f(
        "PROTO-05",
        "fail",
        f"GET returned HTTP {status} ({content_type or 'no content-type'}); expected 405 or an SSE stream.",
        http_status=status,
        content_type=content_type,
    )


async def _check_bogus_session(
    client: httpx.AsyncClient, url: str, sess: dict[str, str], rid: int
) -> Finding:
    if "Mcp-Session-Id" not in sess:
        return _f(
            "PROTO-06",
            "pass",
            "Server is stateless: no Mcp-Session-Id was issued.",
            stateless=True,
        )
    headers = dict(sess)
    headers["Mcp-Session-Id"] = BOGUS_SESSION_ID
    r = await _post(client, url, _rpc("tools/list", rid), headers)
    if r.status == 404:
        return _f("PROTO-06", "pass", "Unknown Mcp-Session-Id got 404.", http_status=404)
    return _f(
        "PROTO-06",
        "fail",
        f"Unknown Mcp-Session-Id got HTTP {r.status}; the spec requires 404.",
        http_status=r.status,
    )


def _schema_problem(label: str, field: str, schema: Any) -> str | None:
    if not isinstance(schema, dict):
        return f"{label}: {field} is not an object"
    try:
        validator_for(schema, default=Draft202012Validator).check_schema(schema)
    except js_exceptions.SchemaError as exc:
        return f"{label}: {field} is not a valid JSON Schema: {exc.message}"
    return None


def _tool_problems(index: int, tool: Any) -> list[str]:
    if not isinstance(tool, dict):
        return [f"tool #{index} is not an object"]
    name = tool.get("name")
    label = name if isinstance(name, str) and name else f"tool #{index}"
    problems: list[str] = []
    if not isinstance(name, str) or not name:
        problems.append(f"{label}: missing or empty name")
    input_schema = tool.get("inputSchema")
    problem = _schema_problem(label, "inputSchema", input_schema)
    if problem:
        problems.append(problem)
    elif input_schema.get("type") != "object":
        problems.append(f"{label}: inputSchema.type must be 'object'")
    if "outputSchema" in tool and tool["outputSchema"] is not None:
        problem = _schema_problem(label, "outputSchema", tool["outputSchema"])
        if problem:
            problems.append(problem)
    return problems


async def _check_tools_list(
    client: httpx.AsyncClient, url: str, sess: dict[str, str], ids: "itertools.count[int]"
) -> Finding:
    tools: list[Any] = []
    cursor: str | None = None
    for _page in range(MAX_TOOL_PAGES):
        rid = next(ids)
        params = {"cursor": cursor} if cursor else {}
        r = await _post(client, url, _rpc("tools/list", rid, params), sess)
        reply = _reply(r, rid)
        if r.status != 200 or reply is None or not isinstance(reply.get("result"), dict):
            return _f(
                "PROTO-07",
                "fail",
                f"tools/list did not return a result (HTTP {r.status}).",
                http_status=r.status,
                parse_error=r.parse_error,
                reply=reply,
            )
        page = reply["result"].get("tools")
        if not isinstance(page, list):
            return _f("PROTO-07", "fail", "tools/list result has no 'tools' array.", result=reply["result"])
        tools.extend(page)
        cursor = reply["result"].get("nextCursor")
        if not cursor:
            break
    else:
        return _f(
            "PROTO-07",
            "fail",
            f"tools/list kept returning nextCursor after {MAX_TOOL_PAGES} pages.",
        )
    problems: list[str] = []
    for index, tool in enumerate(tools):
        problems.extend(_tool_problems(index, tool))
    if problems:
        return _f(
            "PROTO-07",
            "fail",
            f"{len(problems)} schema problem(s) in tools/list.",
            tool_count=len(tools),
            problems=problems[:10],
        )
    return _f("PROTO-07", "pass", f"All {len(tools)} tools have valid schemas.", tool_count=len(tools))


async def _check_unknown_method(
    client: httpx.AsyncClient, url: str, sess: dict[str, str], rid: int
) -> Finding:
    r = await _post(client, url, _rpc("sayable/does-not-exist", rid), sess)
    reply = _reply(r, rid)
    code = None
    if reply is not None and isinstance(reply.get("error"), dict):
        code = reply["error"].get("code")
    if code == -32601 and r.status < 500:
        return _f(
            "PROTO-08",
            "pass",
            "Unknown method returned JSON-RPC error -32601.",
            http_status=r.status,
            error_code=code,
        )
    return _f(
        "PROTO-08",
        "fail",
        f"Unknown method returned HTTP {r.status} with error code {code!r}; expected JSON-RPC -32601 and HTTP below 500.",
        http_status=r.status,
        error_code=code,
        parse_error=r.parse_error,
    )


async def run(url: str) -> list[Finding]:
    ids = itertools.count(1)
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False) as client:
        init_id = next(ids)
        init_payload = _rpc(
            "initialize",
            init_id,
            {
                "protocolVersion": MIN_PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "sayable-lint", "version": __version__},
            },
        )
        original_url = url
        try:
            init = await _post(client, url, init_payload, {})
            # Many servers answer POST /mcp with 307 -> /mcp/ (Starlette mounts). Real clients follow that,
            # so we resolve the canonical endpoint once and run every check against it. Same host only.
            for _ in range(MAX_REDIRECTS):
                if init.status not in REDIRECT_STATUSES:
                    break
                target = _redirect_target(url, init.headers.get("location"))
                if target is None:
                    break
                url = target
                init = await _post(client, url, init_payload, {})
        except httpx.HTTPError as exc:
            raise ProtocolCheckError(
                f"cannot reach {url}: {type(exc).__name__}: {exc}. "
                "Start the server, or check the URL (Streamable HTTP endpoints usually end in /mcp)."
            ) from exc

        proto01, negotiated = _proto01(init, init_id)
        if url != original_url and proto01.severity == "pass":
            proto01 = replace(
                proto01,
                message=f"{proto01.message} Endpoint redirected from {original_url} to {url}; checks ran against the final URL.",
                evidence={**proto01.evidence, "redirected_from": original_url, "endpoint": url},
            )
        findings: list[Finding] = [proto01, _proto09(init)]

        if negotiated is None:
            findings.extend(_blocked(f"PROTO-0{n}") for n in (2, 3, 4, 5, 6, 7, 8))
        else:
            sess = {"MCP-Protocol-Version": negotiated}
            session_id = init.headers.get("mcp-session-id")
            if session_id:
                sess["Mcp-Session-Id"] = session_id
            findings.append(await _guard("PROTO-03", _check_initialized(client, url, sess)))
            findings.append(
                await _guard("PROTO-02", _check_bad_version(client, url, sess, next(ids)))
            )
            findings.append(
                await _guard("PROTO-04", _check_bad_origin(client, url, sess, next(ids)))
            )
            findings.append(await _guard("PROTO-05", _check_get(client, url, sess)))
            findings.append(
                await _guard("PROTO-06", _check_bogus_session(client, url, sess, next(ids)))
            )
            findings.append(await _guard("PROTO-07", _check_tools_list(client, url, sess, ids)))
            findings.append(
                await _guard("PROTO-08", _check_unknown_method(client, url, sess, next(ids)))
            )
    return sorted(findings, key=lambda f: f.check_id)