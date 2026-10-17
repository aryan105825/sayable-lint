# @exports: speech_findings(tool: str, text: str, structured: dict | None, output_schema: dict | None, max_words: int = 45, is_error: bool = False) -> list[Finding]  # SPEECH-01..06, plus SPEECH-07 only when is_error
# @exports: latency_findings(snap: Snapshot, probes: list[ProbeResult], budget_ms: float = 800) -> list[Finding]  # LAT-01, LAT-02, then LAT-03 per probed tool
# @exports: run(url: str, snap: Snapshot, probe_args: dict[str, dict], max_words: int = 45, latency_budget_ms: float = 800, repeats: int = 10) -> tuple[list[Finding], list[ProbeResult]]
# @imports: sayable/mcp_client.py:probe_many(url, calls, repeats)
# @imports: sayable/schemas.py:Finding, ProbeResult, Severity, Snapshot
# @env: (none)
# @schema: probe_args maps tool name -> arguments dict; only tools named there are ever called; an unknown tool name raises ValueError
# @schema: empty probe_args -> single SPEECH-00 warn, no tools are called; latency findings from the snapshot still run
# @schema: speech findings use the FIRST probe reply per tool; LAT-03 uses all repeats (nearest-rank p95)
# @schema: all findings are kind="heuristic"; categories "speech" and "latency"; evidence includes tool and a reply excerpt (<= 300 chars)
# @schema: SPEECH-01 words <= max_words; 02 no markdown/table chars; 03 no URL/ISO date-time/UUID; 04 not raw JSON; 05 no emoji; 06 structuredContent present and valid vs outputSchema; 07 error reply <= 25 words, no traceback
# @schema: LAT-01 initialize <= 1500 ms; LAT-02 tools/list <= 500 ms; LAT-03 per-tool p95 <= budget_ms
from __future__ import annotations

import json
import math
import re
from typing import Any

from jsonschema.validators import Draft202012Validator, validator_for

from sayable.mcp_client import probe_many
from sayable.schemas import Finding, ProbeResult, Severity, Snapshot

ERROR_MAX_WORDS = 25
INIT_BUDGET_MS = 1500.0
LIST_TOOLS_BUDGET_MS = 500.0
EXCERPT_CHARS = 300

_MARKDOWN_PATTERNS: dict[str, re.Pattern[str]] = {
    "table pipe": re.compile(r"\|"),
    "bold or underline emphasis": re.compile(r"\*\*|__"),
    "code backtick": re.compile(r"`"),
    "heading": re.compile(r"^\s{0,3}#{1,6}\s", re.M),
    "bullet": re.compile(r"^\s*[-*+]\s+\S", re.M),
    "numbered list": re.compile(r"^\s*\d+[.)]\s+\S", re.M),
    "link": re.compile(r"\[[^\]]+\]\([^)]+\)"),
    "horizontal rule": re.compile(r"^\s*-{3,}\s*$", re.M),
}
_URL = re.compile(r"https?://\S+|\bwww\.\S+")
_ISO = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F\u200D]")
_TRACEBACK = re.compile(
    r"Traceback \(most recent call last\)|File \".+\", line \d+|^\s+at .+\(.+:\d+(?::\d+)?\)",
    re.M,
)


def _finding(
    check_id: str, category: str, severity: Severity, message: str, evidence: dict[str, Any]
) -> Finding:
    return Finding(
        check_id=check_id,
        category=category,  # type: ignore[arg-type]
        kind="heuristic",
        severity=severity,
        message=message,
        evidence=evidence,
    )


def _excerpt(text: str) -> str:
    return text if len(text) <= EXCERPT_CHARS else text[:EXCERPT_CHARS] + "..."


def _is_raw_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return False
    return isinstance(parsed, (dict, list))


def speech_findings(
    tool: str,
    text: str,
    structured: dict | None,
    output_schema: dict | None,
    max_words: int = 45,
    is_error: bool = False,
) -> list[Finding]:
    base: dict[str, Any] = {"tool": tool, "reply": _excerpt(text)}
    words = len(text.split())
    out: list[Finding] = []

    out.append(
        _finding(
            "SPEECH-01",
            "speech",
            "pass" if words <= max_words else "fail",
            f"{tool}: reply is {words} words (limit {max_words}).",
            {**base, "words": words, "max_words": max_words},
        )
    )

    markdown_hits = [name for name, pattern in _MARKDOWN_PATTERNS.items() if pattern.search(text)]
    out.append(
        _finding(
            "SPEECH-02",
            "speech",
            "fail" if markdown_hits else "pass",
            f"{tool}: reply contains markdown or table characters ({', '.join(markdown_hits)})."
            if markdown_hits
            else f"{tool}: reply has no markdown or table characters.",
            {**base, "matches": markdown_hits},
        )
    )

    unspeakable = []
    if _URL.search(text):
        unspeakable.append("URL")
    if _ISO.search(text):
        unspeakable.append("ISO date or timestamp")
    if _UUID.search(text):
        unspeakable.append("UUID")
    out.append(
        _finding(
            "SPEECH-03",
            "speech",
            "fail" if unspeakable else "pass",
            f"{tool}: reply contains unspeakable data ({', '.join(unspeakable)})."
            if unspeakable
            else f"{tool}: reply has no URL, ISO timestamp or UUID.",
            {**base, "matches": unspeakable},
        )
    )

    raw_json = _is_raw_json(text)
    out.append(
        _finding(
            "SPEECH-04",
            "speech",
            "fail" if raw_json else "pass",
            f"{tool}: reply text is raw JSON." if raw_json else f"{tool}: reply text is not raw JSON.",
            base,
        )
    )

    emoji = sorted(set(_EMOJI.findall(text)))
    out.append(
        _finding(
            "SPEECH-05",
            "speech",
            "fail" if emoji else "pass",
            f"{tool}: reply contains emoji or symbols a speech engine reads aloud awkwardly."
            if emoji
            else f"{tool}: reply has no emoji.",
            {**base, "matches": emoji},
        )
    )

    if structured is None:
        out.append(
            _finding(
                "SPEECH-06",
                "speech",
                "fail",
                f"{tool}: no structuredContent returned alongside the spoken text.",
                base,
            )
        )
    else:
        schema_errors: list[str] = []
        if output_schema is not None:
            validator = validator_for(output_schema, default=Draft202012Validator)(output_schema)
            errors = sorted(validator.iter_errors(structured), key=lambda e: str(list(e.path)))
            schema_errors = [e.message for e in errors[:3]]
        out.append(
            _finding(
                "SPEECH-06",
                "speech",
                "fail" if schema_errors else "pass",
                f"{tool}: structuredContent does not match the declared outputSchema."
                if schema_errors
                else f"{tool}: structuredContent present"
                + (" and valid against outputSchema." if output_schema is not None else "."),
                {**base, "schema_errors": schema_errors, "has_output_schema": output_schema is not None},
            )
        )

    if is_error:
        has_traceback = bool(_TRACEBACK.search(text))
        too_long = words > ERROR_MAX_WORDS
        problems = []
        if too_long:
            problems.append(f"{words} words (limit {ERROR_MAX_WORDS})")
        if has_traceback:
            problems.append("contains a stack trace")
        out.append(
            _finding(
                "SPEECH-07",
                "speech",
                "fail" if problems else "pass",
                f"{tool}: error reply is " + " and ".join(problems) + "."
                if problems
                else f"{tool}: error reply is short and has no stack trace.",
                {**base, "words": words, "traceback": has_traceback},
            )
        )
    return out


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    rank = math.ceil(0.95 * len(ordered))
    return ordered[rank - 1]


def latency_findings(
    snap: Snapshot, probes: list[ProbeResult], budget_ms: float = 800
) -> list[Finding]:
    out: list[Finding] = [
        _finding(
            "LAT-01",
            "latency",
            "pass" if snap.init_ms <= INIT_BUDGET_MS else "fail",
            f"initialize took {snap.init_ms:.0f} ms (budget {INIT_BUDGET_MS:.0f} ms).",
            {"init_ms": round(snap.init_ms, 1), "budget_ms": INIT_BUDGET_MS},
        ),
        _finding(
            "LAT-02",
            "latency",
            "pass" if snap.list_tools_ms <= LIST_TOOLS_BUDGET_MS else "fail",
            f"tools/list took {snap.list_tools_ms:.0f} ms (budget {LIST_TOOLS_BUDGET_MS:.0f} ms).",
            {"list_tools_ms": round(snap.list_tools_ms, 1), "budget_ms": LIST_TOOLS_BUDGET_MS},
        ),
    ]
    by_tool: dict[str, list[float]] = {}
    for probe in probes:
        by_tool.setdefault(probe.tool, []).append(probe.latency_ms)
    for tool, values in by_tool.items():
        p95 = _p95(values)
        out.append(
            _finding(
                "LAT-03",
                "latency",
                "pass" if p95 <= budget_ms else "fail",
                f"{tool}: p95 latency {p95:.0f} ms over {len(values)} calls (budget {budget_ms:.0f} ms).",
                {
                    "tool": tool,
                    "calls": len(values),
                    "p95_ms": round(p95, 1),
                    "max_ms": round(max(values), 1),
                    "budget_ms": budget_ms,
                },
            )
        )
    return out


async def run(
    url: str,
    snap: Snapshot,
    probe_args: dict[str, dict],
    max_words: int = 45,
    latency_budget_ms: float = 800,
    repeats: int = 10,
) -> tuple[list[Finding], list[ProbeResult]]:
    if not probe_args:
        findings = [
            _finding(
                "SPEECH-00",
                "speech",
                "warn",
                "No probe arguments given, so no tool was called and replies were not checked. "
                "Pass --probe-args FILE naming the read-only tools to probe.",
                {},
            )
        ]
        findings.extend(latency_findings(snap, [], latency_budget_ms))
        return findings, []

    tools = {t.name: t for t in snap.tools}
    unknown = sorted(name for name in probe_args if name not in tools)
    if unknown:
        raise ValueError(
            f"probe args name tools that {url} does not expose: {', '.join(unknown)}. "
            f"Available tools: {', '.join(sorted(tools)) or '(none)'}."
        )

    probes = await probe_many(url, list(probe_args.items()), repeats)
    first_by_tool: dict[str, ProbeResult] = {}
    for probe in probes:
        first_by_tool.setdefault(probe.tool, probe)

    findings: list[Finding] = []
    for name in probe_args:
        probe = first_by_tool[name]
        findings.extend(
            speech_findings(
                name,
                probe.text,
                probe.structured,
                tools[name].output_schema,
                max_words,
                is_error=probe.is_error,
            )
        )
    findings.extend(latency_findings(snap, probes, latency_budget_ms))
    return findings, probes
