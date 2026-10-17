# @exports: load_probe_args(path: str, server_name: str) -> dict[str, dict]  # entry for server_name from the probe file; {} if the file has no entry; ValueError on bad shape or invalid JSON
# @exports: lint_url(url: str, probe_file: str | None, max_words: int = 45, latency_ms: float = 800, repeats: int = 10) -> tuple[Report, Snapshot]  # async; order: protocol checks, snapshot, design, speech+latency
# @exports: format_scorecard(report: Report, snap: Snapshot) -> str
# @exports: main(argv: list[str] | None = None) -> int  # exit 0; 1 if total < --min-score; 2 on error (message on stderr)
# @imports: sayable/__init__.py:__version__
# @imports: sayable/checks_protocol.py:run, ProtocolCheckError
# @imports: sayable/checks_design.py:run
# @imports: sayable/checks_speech.py:run
# @imports: sayable/report_html.py:render
# @imports: sayable/mcp_client.py:snapshot, wait_ready
# @imports: sayable/schemas.py:CATEGORY_MAX, Report, Snapshot, score
# @env: (none)
# @schema: CLI: sayable-lint URL [--probe-args FILE] [--max-words 45] [--latency-ms 800] [--repeats 10] [--out P] [--html P] [--min-score N] [--wait]
# @schema: probe file is JSON {"<serverInfo.name>": {"<tool>": {args}}}; the entry is chosen by the server's own name; without --probe-args no tool is called (SPEECH-00 warn)
# @schema: --out JSON = Report.to_dict() plus "server": {"name", "version", "tool_count"}
# @schema: findings are ordered by category (protocol, latency, speech, design) then check_id; ties keep insertion order
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from sayable import __version__, checks_design, checks_protocol, checks_speech, report_html
from sayable.mcp_client import snapshot, wait_ready
from sayable.schemas import CATEGORY_MAX, Report, Snapshot, score


def load_probe_args(path: str, server_name: str) -> dict[str, dict]:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be an object keyed by server name")
    entry = data.get(server_name)
    if entry is None:
        return {}
    if not isinstance(entry, dict):
        raise ValueError(f"{path}: entry for {server_name!r} must be an object of tool -> arguments")
    for tool, args in entry.items():
        if not isinstance(args, dict):
            raise ValueError(f"{path}: arguments for {server_name}.{tool} must be a JSON object")
    return dict(entry)


async def lint_url(
    url: str,
    probe_file: str | None,
    max_words: int = 45,
    latency_ms: float = 800,
    repeats: int = 10,
) -> tuple[Report, Snapshot]:
    protocol_findings = await checks_protocol.run(url)
    snap = await snapshot(url)
    design_findings = checks_design.run(snap)

    probe_args: dict[str, dict] = {}
    if probe_file is not None:
        probe_args = load_probe_args(probe_file, snap.server_name)
        if not probe_args:
            print(
                f"sayable-lint: note: {probe_file} has no entry for server {snap.server_name!r}; "
                "no tools will be probed.",
                file=sys.stderr,
            )
    speech_latency_findings, _probes = await checks_speech.run(
        url, snap, probe_args, max_words, latency_ms, repeats
    )

    order = {category: i for i, category in enumerate(CATEGORY_MAX)}
    findings = sorted(
        protocol_findings + speech_latency_findings + design_findings,
        key=lambda f: (order[f.category], f.check_id),
    )
    category_scores, total, spec_score, heuristic_score = score(findings)
    report = Report(
        url=url,
        negotiated_protocol=snap.negotiated_protocol,
        findings=findings,
        category_scores=category_scores,
        total=total,
        spec_score=spec_score,
        heuristic_score=heuristic_score,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sayable_version=__version__,
    )
    return report, snap


def format_scorecard(report: Report, snap: Snapshot) -> str:
    lines = [
        f"Sayable scorecard for {report.url}",
        f"server: {snap.server_name} {snap.server_version}   protocol: {report.negotiated_protocol}",
        "",
        f"SPEC score       {report.spec_score:>3}/100  (protocol checks from the MCP spec)",
        f"HEURISTIC score  {report.heuristic_score:>3}/100  (latency + speech + design; configurable opinions)",
        f"TOTAL            {report.total:>3}/100",
        "",
    ]
    for category, maximum in CATEGORY_MAX.items():
        lines.append(f"  {category:<9} {report.category_scores[category]:>2}/{maximum}")
    lines.append("")
    passed = 0
    for f in report.findings:
        if f.severity == "pass":
            passed += 1
        else:
            lines.append(f"  [{f.severity.upper()}] {f.check_id} {f.message}")
    lines.append(f"{passed} of {len(report.findings)} checks passed")
    return "\n".join(lines)


def _write(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _bounded_int(low: int, high: int | None, name: str):
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer, got {text!r}") from exc
        if value < low or (high is not None and value > high):
            bound = f">= {low}" if high is None else f"between {low} and {high}"
            raise argparse.ArgumentTypeError(f"{name} must be {bound}, got {value}")
        return value

    return parse


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sayable-lint",
        description="Voice-readiness linter for Streamable HTTP MCP servers.",
    )
    p.add_argument("url", help="MCP endpoint, e.g. http://127.0.0.1:8801/mcp")
    p.add_argument("--probe-args", metavar="FILE", help="JSON file naming the read-only tools to call")
    p.add_argument("--max-words", type=_bounded_int(1, None, "--max-words"), default=45)
    p.add_argument("--latency-ms", type=_bounded_int(1, None, "--latency-ms"), default=800)
    p.add_argument("--repeats", type=_bounded_int(1, None, "--repeats"), default=10)
    p.add_argument("--out", metavar="PATH", help="write the JSON report here")
    p.add_argument("--html", metavar="PATH", help="write the single-file HTML report here")
    p.add_argument("--min-score", type=_bounded_int(0, 100, "--min-score"), default=None)
    p.add_argument("--wait", action="store_true", help="wait up to 20 s for the server to answer initialize")
    return p


async def _amain(ns: argparse.Namespace) -> int:
    if ns.wait:
        await wait_ready(ns.url)
    report, snap = await lint_url(
        ns.url, ns.probe_args, ns.max_words, float(ns.latency_ms), ns.repeats
    )
    print(format_scorecard(report, snap))
    if ns.out:
        payload = report.to_dict()
        payload["server"] = {
            "name": snap.server_name,
            "version": snap.server_version,
            "tool_count": len(snap.tools),
        }
        _write(ns.out, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {ns.out}", file=sys.stderr)
    if ns.html:
        _write(ns.html, report_html.render(report, snap))
        print(f"wrote {ns.html}", file=sys.stderr)
    if ns.min_score is not None and report.total < ns.min_score:
        print(
            f"sayable-lint: total {report.total} is below --min-score {ns.min_score}",
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _parser().parse_args(argv)
    try:
        return asyncio.run(_amain(ns))
    except (checks_protocol.ProtocolCheckError, TimeoutError, ValueError, RuntimeError, OSError) as exc:
        print(f"sayable-lint: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
