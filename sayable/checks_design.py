# @exports: run(snap: Snapshot) -> list[Finding]  # DES-01..06, one finding each, kind="heuristic", category="design"
# @imports: sayable/schemas.py:Finding, Severity, Snapshot, ToolInfo
# @env: (none)
# @schema: DES-01 readOnlyHint and destructiveHint both set explicitly (bool) on every tool
# @schema: DES-02 every non-read-only tool (readOnlyHint is not true) has a parameter whose name starts with "confirm"; pass if there are none
# @schema: DES-03 description length 20..300 characters; DES-04 no description pair with word-Jaccard >= 0.5; DES-05 <= 15 tools; DES-06 <= 3 required parameters per tool
# @schema: per-tool checks grade by share of tools OK: all -> pass, >= 50% -> warn, else fail; a server with no tools gets six warns
from __future__ import annotations

import re
from itertools import combinations

from sayable.schemas import Finding, Severity, Snapshot, ToolInfo

MAX_TOOLS = 15
MAX_REQUIRED = 3
MIN_DESC_CHARS = 20
MAX_DESC_CHARS = 300
JACCARD_LIMIT = 0.5


def _finding(check_id: str, severity: Severity, message: str, evidence: dict) -> Finding:
    return Finding(
        check_id=check_id,
        category="design",
        kind="heuristic",
        severity=severity,
        message=message,
        evidence=evidence,
    )


def _graded(check_id: str, total: int, bad: list[str], ok_message: str, bad_message: str) -> Finding:
    ok = total - len(bad)
    evidence = {"tools_checked": total, "offending_tools": bad}
    if not bad:
        return _finding(check_id, "pass", ok_message, evidence)
    severity: Severity = "warn" if ok * 2 >= total else "fail"
    return _finding(check_id, severity, f"{bad_message}: {', '.join(bad)}.", evidence)


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _is_read_only(tool: ToolInfo) -> bool:
    return tool.annotations.get("readOnlyHint") is True


def _explicit_hints(tool: ToolInfo) -> bool:
    return isinstance(tool.annotations.get("readOnlyHint"), bool) and isinstance(
        tool.annotations.get("destructiveHint"), bool
    )


def _has_confirm_param(tool: ToolInfo) -> bool:
    properties = tool.input_schema.get("properties", {})
    return any(str(name).lower().startswith("confirm") for name in properties)


def run(snap: Snapshot) -> list[Finding]:
    tools = snap.tools
    ids = ["DES-01", "DES-02", "DES-03", "DES-04", "DES-05", "DES-06"]
    if not tools:
        return [
            _finding(check_id, "warn", "Server exposes no tools, so there is nothing to evaluate.", {})
            for check_id in ids
        ]

    findings: list[Finding] = []

    findings.append(
        _graded(
            "DES-01",
            len(tools),
            [t.name for t in tools if not _explicit_hints(t)],
            "Every tool sets readOnlyHint and destructiveHint explicitly.",
            "Tools missing an explicit readOnlyHint or destructiveHint",
        )
    )

    writers = [t for t in tools if not _is_read_only(t)]
    if not writers:
        findings.append(
            _finding(
                "DES-02",
                "pass",
                "No state-changing tools, so no confirmation parameter is needed.",
                {"tools_checked": 0, "offending_tools": []},
            )
        )
    else:
        findings.append(
            _graded(
                "DES-02",
                len(writers),
                [t.name for t in writers if not _has_confirm_param(t)],
                "Every non-read-only tool has a confirm* parameter.",
                "Non-read-only tools without a confirm* parameter",
            )
        )

    findings.append(
        _graded(
            "DES-03",
            len(tools),
            [
                t.name
                for t in tools
                if not MIN_DESC_CHARS <= len(t.description.strip()) <= MAX_DESC_CHARS
            ],
            f"Every description is {MIN_DESC_CHARS}-{MAX_DESC_CHARS} characters.",
            f"Descriptions outside {MIN_DESC_CHARS}-{MAX_DESC_CHARS} characters",
        )
    )

    similar: list[dict] = []
    word_sets = {t.name: _words(t.description) for t in tools}
    for a, b in combinations(tools, 2):
        j = _jaccard(word_sets[a.name], word_sets[b.name])
        if j >= JACCARD_LIMIT:
            similar.append({"tools": [a.name, b.name], "jaccard": round(j, 2)})
    if similar:
        pairs = ", ".join(f"{p['tools'][0]}/{p['tools'][1]}" for p in similar)
        findings.append(
            _finding(
                "DES-04",
                "fail",
                f"Tool descriptions are too similar for a model to tell apart: {pairs}.",
                {"similar_pairs": similar, "limit": JACCARD_LIMIT},
            )
        )
    else:
        findings.append(
            _finding(
                "DES-04",
                "pass",
                f"No pair of descriptions has word overlap >= {JACCARD_LIMIT}.",
                {"similar_pairs": [], "limit": JACCARD_LIMIT},
            )
        )

    findings.append(
        _finding(
            "DES-05",
            "pass" if len(tools) <= MAX_TOOLS else "fail",
            f"Server exposes {len(tools)} tools (limit {MAX_TOOLS}).",
            {"tool_count": len(tools), "limit": MAX_TOOLS},
        )
    )

    findings.append(
        _graded(
            "DES-06",
            len(tools),
            [t.name for t in tools if len(t.input_schema.get("required", [])) > MAX_REQUIRED],
            f"No tool has more than {MAX_REQUIRED} required parameters.",
            f"Tools with more than {MAX_REQUIRED} required parameters",
        )
    )
    return findings
