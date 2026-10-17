# @exports: render(report: Report, snap: Snapshot) -> str  # complete single-file HTML document, inline CSS, no external resources, all dynamic text HTML-escaped
# @imports: sayable/schemas.py:Report, Snapshot, CATEGORY_MAX
# @env: (none)
# @schema: shows "Spec score" and "Heuristic score" separately, with a one-line note that heuristics are configurable
# @schema: one table row per finding with ID, kind, severity, message and collapsible JSON evidence (evidence must be JSON-serialisable or json.dumps raises TypeError)
from __future__ import annotations

import html
import json

from sayable.schemas import CATEGORY_MAX, Report, Snapshot

_CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f5f5f7;--line:#d8d8dc;--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#111;--fg:#eee;--muted:#9a9a9a;--card:#1c1c1e;--line:#333;--pass:#3fb950;--warn:#d29922;--fail:#f85149}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:1000px;margin-inline:auto}
h1{margin:0 0 4px;font-size:24px}h2{margin:32px 0 8px;font-size:18px}
.muted{color:var(--muted)}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{flex:1 1 180px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .n{font-size:34px;font-weight:700}.card .l{font-size:13px;color:var(--muted)}
.good{color:var(--pass)}.mid{color:var(--warn)}.bad{color:var(--fail)}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}
.sev-pass{color:var(--pass)}.sev-warn{color:var(--warn)}.sev-fail{color:var(--fail)}
.kind{font-size:12px;border:1px solid var(--line);border-radius:4px;padding:1px 6px}
pre{margin:6px 0 0;padding:8px;background:var(--card);border-radius:6px;overflow-x:auto;font-size:12px}
.wrap{overflow-x:auto}
"""


def _band(value: int) -> str:
    if value >= 85:
        return "good"
    if value >= 60:
        return "mid"
    return "bad"


def _card(label: str, value: int, note: str) -> str:
    esc = html.escape
    return (
        f'<div class="card"><div class="n {_band(value)}">{value}</div>'
        f'<div><strong>{esc(label)}</strong></div><div class="l">{esc(note)}</div></div>'
    )


def render(report: Report, snap: Snapshot) -> str:
    esc = html.escape
    parts: list[str] = []
    parts.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>Sayable scorecard: {esc(report.url)}</title><style>{_CSS}</style></head><body>")
    parts.append(f"<h1>Sayable scorecard</h1><div class=\"muted\">{esc(report.url)}</div>")
    parts.append(
        f'<div class="muted">server {esc(snap.server_name)} {esc(snap.server_version)} &middot; '
        f"protocol {esc(report.negotiated_protocol)} &middot; generated {esc(report.generated_at)} &middot; "
        f"sayable-lint {esc(report.sayable_version)}</div>"
    )
    parts.append('<div class="cards">')
    parts.append(_card("Spec score", report.spec_score, "protocol checks derived from the MCP specification"))
    parts.append(
        _card("Heuristic score", report.heuristic_score, "latency, speech and design checks")
    )
    parts.append(_card("Total", report.total, "weighted 0-100 across all categories"))
    parts.append("</div>")
    parts.append(
        '<p class="muted">Heuristic checks are configurable opinions about voice UX '
        "(thresholds are set with --max-words and --latency-ms); spec checks are not.</p>"
    )

    parts.append("<h2>Category scores</h2><div class=\"wrap\"><table><tr><th>Category</th><th>Score</th></tr>")
    for category, maximum in CATEGORY_MAX.items():
        parts.append(
            f"<tr><td>{esc(category)}</td><td>{report.category_scores[category]} / {maximum}</td></tr>"
        )
    parts.append("</table></div>")

    parts.append(f"<h2>Tools ({len(snap.tools)})</h2>")
    parts.append(
        '<div class="wrap"><table><tr><th>Name</th><th>readOnlyHint</th><th>destructiveHint</th>'
        "<th>Description</th></tr>"
    )
    for tool in snap.tools:
        read_only = tool.annotations.get("readOnlyHint", "unset")
        destructive = tool.annotations.get("destructiveHint", "unset")
        parts.append(
            f"<tr><td>{esc(tool.name)}</td><td>{esc(str(read_only))}</td>"
            f"<td>{esc(str(destructive))}</td><td>{esc(tool.description)}</td></tr>"
        )
    parts.append("</table></div>")

    parts.append(f"<h2>Findings ({len(report.findings)})</h2>")
    parts.append(
        '<div class="wrap"><table><tr><th>ID</th><th>Kind</th><th>Result</th><th>Detail</th></tr>'
    )
    for finding in report.findings:
        evidence = json.dumps(finding.evidence, indent=2, sort_keys=True, ensure_ascii=False)
        parts.append(
            f"<tr><td>{esc(finding.check_id)}</td>"
            f'<td><span class="kind">{esc(finding.kind)}</span></td>'
            f'<td><span class="sev sev-{esc(finding.severity)}">{esc(finding.severity)}</span></td>'
            f"<td>{esc(finding.message)}"
            f"<details><summary class=\"muted\">evidence</summary><pre>{esc(evidence)}</pre></details></td></tr>"
        )
    parts.append("</table></div></body></html>")
    return "".join(parts)
