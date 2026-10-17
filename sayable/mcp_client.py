# @exports: wait_ready(url: str, timeout_s: float = 20.0) -> None  # polls a real initialize; raises TimeoutError with the last error
# @exports: snapshot(url: str, timeout_s: float = 10.0) -> Snapshot
# @exports: call_tool(url: str, name: str, args: dict, timeout_s: float = 10.0) -> ProbeResult
# @exports: probe_many(url: str, calls: list[tuple[str, dict]], repeats: int = 10) -> list[ProbeResult]  # ordered by call, then repeat
# @exports: main(argv: list[str] | None = None) -> int
# @imports: sayable/schemas.py:Snapshot, ToolInfo, ProbeResult
# @env: (none)
# @schema: CLI: python -m sayable.mcp_client URL [--call TOOL --args JSON]
# @schema: every call opens and closes its own client inside a single task (avoids anyio cancel-scope errors)
# @schema: init_ms times only the initialize round trip; list_tools_ms only tools/list; ProbeResult.latency_ms only the tools/call round trip
# @schema: snapshot raises RuntimeError if tools/list is paginated (nextCursor present)
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any, Awaitable, Callable, TypeVar

from mcp import ClientSession

try:
    from mcp.client.streamable_http import streamable_http_client as _http_client
except ImportError:
    from mcp.client.streamable_http import streamablehttp_client as _http_client

from sayable.schemas import ProbeResult, Snapshot, ToolInfo

T = TypeVar("T")


async def _with_session(
    url: str, work: Callable[[ClientSession], Awaitable[T]], timeout_s: float
) -> T:
    async def inner() -> T:
        async with _http_client(url) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                return await work(session)

    try:
        return await asyncio.wait_for(inner(), timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(
            f"timed out after {timeout_s}s talking to {url}. "
            "Check that the server is running and the URL is the Streamable HTTP endpoint (usually ending in /mcp)."
        ) from exc


def _tool_info(tool: Any) -> ToolInfo:
    annotations: dict[str, Any] = {}
    if tool.annotations is not None:
        annotations = tool.annotations.model_dump(exclude_none=True)
    return ToolInfo(
        name=tool.name,
        description=tool.description or "",
        input_schema=dict(tool.inputSchema),
        output_schema=getattr(tool, "outputSchema", None),
        annotations=annotations,
    )


async def snapshot(url: str, timeout_s: float = 10.0) -> Snapshot:
    async def work(session: ClientSession) -> Snapshot:
        t0 = time.perf_counter()
        init = await session.initialize()
        t1 = time.perf_counter()
        listed = await session.list_tools()
        t2 = time.perf_counter()
        if listed.nextCursor:
            raise RuntimeError(
                f"{url} paginates tools/list (nextCursor present); sayable's client reads one page only. "
                "Reduce the server's tool count or extend sayable/mcp_client.py."
            )
        return Snapshot(
            url=url,
            negotiated_protocol=str(init.protocolVersion),
            server_name=init.serverInfo.name,
            server_version=init.serverInfo.version,
            tools=[_tool_info(t) for t in listed.tools],
            init_ms=(t1 - t0) * 1000.0,
            list_tools_ms=(t2 - t1) * 1000.0,
        )

    return await _with_session(url, work, timeout_s)


async def call_tool(url: str, name: str, args: dict, timeout_s: float = 10.0) -> ProbeResult:
    async def work(session: ClientSession) -> ProbeResult:
        await session.initialize()
        t0 = time.perf_counter()
        result = await session.call_tool(name, args)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        text = " ".join(
            block.text for block in result.content if getattr(block, "type", None) == "text"
        )
        return ProbeResult(
            tool=name,
            text=text,
            structured=getattr(result, "structuredContent", None),
            is_error=bool(result.isError),
            latency_ms=elapsed_ms,
        )

    return await _with_session(url, work, timeout_s)


async def probe_many(
    url: str, calls: list[tuple[str, dict]], repeats: int = 10
) -> list[ProbeResult]:
    if repeats < 1:
        raise ValueError(f"repeats must be >= 1, got {repeats}")
    results: list[ProbeResult] = []
    for name, args in calls:
        for _ in range(repeats):
            results.append(await call_tool(url, name, args))
    return results


async def wait_ready(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = "no attempt made"
    while True:
        try:
            await snapshot(url, timeout_s=3.0)
            return
        except Exception as exc:  # retried until the deadline, then raised below with the last error
            last_error = f"{type(exc).__name__}: {exc}"
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"{url} did not complete an MCP initialize within {timeout_s}s. Last error: {last_error}. "
                "Start the server, check the port, and confirm the URL ends in /mcp."
            )
        await asyncio.sleep(0.5)


async def _cli(url: str, tool: str | None, args: dict) -> int:
    if tool is None:
        snap = await snapshot(url)
        print(f"server: {snap.server_name} {snap.server_version}")
        print(f"protocol: {snap.negotiated_protocol}")
        print(f"init_ms: {snap.init_ms:.1f}  list_tools_ms: {snap.list_tools_ms:.1f}")
        for t in snap.tools:
            print(f"tool: {t.name}")
        return 0
    result = await call_tool(url, tool, args)
    print(result.text)
    print(json.dumps(result.structured, sort_keys=True))
    print(f"latency_ms: {result.latency_ms:.1f}")
    return 1 if result.is_error else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sayable.mcp_client")
    parser.add_argument("url", help="Streamable HTTP MCP endpoint, e.g. http://127.0.0.1:8801/mcp")
    parser.add_argument("--call", dest="tool", help="tool name to call")
    parser.add_argument("--args", default=None, help="JSON object of tool arguments (requires --call)")
    ns = parser.parse_args(argv)
    if ns.args is not None and ns.tool is None:
        parser.error("--args requires --call TOOL")
    args: dict = {}
    if ns.args is not None:
        try:
            args = json.loads(ns.args)
        except json.JSONDecodeError as exc:
            parser.error(f"--args must be valid JSON: {exc}")
        if not isinstance(args, dict):
            parser.error("--args must be a JSON object, e.g. '{\"name\": \"eggs\"}'")
    return asyncio.run(_cli(ns.url, ns.tool, args))


if __name__ == "__main__":
    sys.exit(main())
