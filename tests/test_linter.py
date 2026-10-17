# @exports: (pytest module, no symbols)
# @imports: sayable/ (linter only; this file must not import pantry so it can ship in the standalone sayable-lint repo)
# @schema: Linter unit tests. No network, no running servers.
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from sayable import checks_design, report_html  # noqa: E402
from sayable.checks_protocol import _redirect_target, parse_response_body  # noqa: E402
from sayable.checks_speech import latency_findings, speech_findings  # noqa: E402
from sayable.lint import format_scorecard, load_probe_args  # noqa: E402
from sayable.schemas import (  # noqa: E402
    Finding,
    ProbeResult,
    Report,
    Snapshot,
    ToolInfo,
    score,
)


# ---------- response parsing ----------


def test_parse_json_body():
    msgs = parse_response_body(
        "application/json; charset=utf-8", '{"jsonrpc":"2.0","id":1,"result":{}}'
    )
    assert msgs == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
    batch = parse_response_body("application/json", '[{"id":1},{"id":2}]')
    assert [m["id"] for m in batch] == [1, 2]


def test_parse_sse_body():
    body = 'event: message\r\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\r\n\r\n'
    assert parse_response_body("text/event-stream", body) == [
        {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    ]


def test_parse_sse_priming_event_and_multiline_data():
    body = (
        "id: 1\ndata:\n\n"
        'event: message\ndata: {"a":\ndata: 1}\n\n'
        ': keep-alive comment\n\n'
        'data: {"b": 2}\n\n'
    )
    assert parse_response_body("text/event-stream", body) == [{"a": 1}, {"b": 2}]


def test_parse_errors_are_loud():
    with pytest.raises(ValueError):
        parse_response_body("text/plain", "hello")
    with pytest.raises(ValueError):
        parse_response_body("application/json", "{not json")
    with pytest.raises(ValueError):
        parse_response_body("application/json", "[1, 2]")


# ---------- speech and latency checks ----------


def _by_id(findings):
    return {f.check_id: f.severity for f in findings}


def test_speech_clean_reply_passes_everything():
    findings = speech_findings("count_item", "You have six eggs.", {"name": "eggs", "quantity": 6}, None)
    assert len(findings) == 6
    assert set(_by_id(findings).values()) == {"pass"}


def test_speech_flags_each_problem():
    structured = {"x": 1}
    long_text = " ".join(["word"] * 46)
    assert _by_id(speech_findings("t", long_text, structured, None))["SPEECH-01"] == "fail"
    assert _by_id(speech_findings("t", "| a | b |\n|---|---|", structured, None))["SPEECH-02"] == "fail"
    assert _by_id(speech_findings("t", "**bold** reply", structured, None))["SPEECH-02"] == "fail"
    assert _by_id(speech_findings("t", "Expires 2026-10-09T00:00:00+00:00", structured, None))["SPEECH-03"] == "fail"
    assert _by_id(speech_findings("t", "See https://example.com now", structured, None))["SPEECH-03"] == "fail"
    assert _by_id(speech_findings("t", '{"a": 1}', structured, None))["SPEECH-04"] == "fail"
    assert _by_id(speech_findings("t", "All done \u2705", structured, None))["SPEECH-05"] == "fail"
    assert _by_id(speech_findings("t", "Fine.", None, None))["SPEECH-06"] == "fail"


def test_speech_output_schema_validation():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}}, "required": ["n"]}
    assert _by_id(speech_findings("t", "Ok.", {"n": 1}, schema))["SPEECH-06"] == "pass"
    assert _by_id(speech_findings("t", "Ok.", {"n": "x"}, schema))["SPEECH-06"] == "fail"


def test_speech_error_reply_rules():
    assert "SPEECH-07" not in _by_id(speech_findings("t", "Fine.", {"x": 1}, None))
    ok = speech_findings("t", "That did not work.", {"error": "x"}, None, is_error=True)
    assert _by_id(ok)["SPEECH-07"] == "pass"
    trace = 'Traceback (most recent call last):\n  File "x.py", line 3, in f'
    bad = speech_findings("t", trace, {"error": "x"}, None, is_error=True)
    assert _by_id(bad)["SPEECH-07"] == "fail"
    wordy = speech_findings("t", " ".join(["oops"] * 26), {"error": "x"}, None, is_error=True)
    assert _by_id(wordy)["SPEECH-07"] == "fail"


def _snap(tools=None, init_ms=10.0, list_ms=5.0):
    return Snapshot("http://x/mcp", "2025-11-25", "srv", "1.0", tools or [], init_ms, list_ms)


def test_latency_findings():
    findings = latency_findings(_snap(init_ms=2000.0, list_ms=100.0), [])
    assert _by_id(findings) == {"LAT-01": "fail", "LAT-02": "pass"}
    fast = [ProbeResult("t", "x", None, False, 100.0) for _ in range(20)]
    assert _by_id(latency_findings(_snap(), fast))["LAT-03"] == "pass"
    slow = [ProbeResult("t", "x", None, False, 100.0) for _ in range(10)] + [
        ProbeResult("t", "x", None, False, 2000.0) for _ in range(10)
    ]
    assert _by_id(latency_findings(_snap(), slow))["LAT-03"] == "fail"


# ---------- design checks ----------


def _tool(name="a", desc="List the items that expire soon in the pantry.", ann=None, props=None, required=None):
    schema = {"type": "object", "properties": props or {}, "required": required or []}
    annotations = {"readOnlyHint": True, "destructiveHint": False} if ann is None else ann
    return ToolInfo(name, desc, schema, None, annotations)


def test_design_good_server_passes():
    tools = [
        _tool("a"),
        _tool(
            "b",
            "Remove pantry items after a spoken confirmation step.",
            ann={"readOnlyHint": False, "destructiveHint": True},
            props={"confirm_token": {"type": "string"}},
        ),
    ]
    findings = checks_design.run(_snap(tools))
    assert [f.check_id for f in findings] == [f"DES-0{i}" for i in range(1, 7)]
    assert set(_by_id(findings).values()) == {"pass"}


def test_design_flags_each_problem():
    assert _by_id(checks_design.run(_snap([_tool(ann={})])))["DES-01"] == "fail"
    writer = _tool(ann={"readOnlyHint": False, "destructiveHint": False})
    assert _by_id(checks_design.run(_snap([writer])))["DES-02"] == "fail"
    assert _by_id(checks_design.run(_snap([_tool(desc="short")])))["DES-03"] == "fail"
    twins = [_tool("a", "List pantry items that expire soon."), _tool("b", "List pantry items that expire soon.")]
    assert _by_id(checks_design.run(_snap(twins)))["DES-04"] == "fail"
    many = [_tool(f"t{i}", f"Tool number {i} does something unique alpha{i} beta{i}.") for i in range(16)]
    assert _by_id(checks_design.run(_snap(many)))["DES-05"] == "fail"
    props = {k: {"type": "string"} for k in "wxyz"}
    assert _by_id(checks_design.run(_snap([_tool(props=props, required=list("wxyz"))])))["DES-06"] == "fail"


def test_design_partial_compliance_is_warn_and_empty_server_warns():
    good = _tool("a")
    bare = _tool("b", "List all the other stuff available here.", ann={})
    assert _by_id(checks_design.run(_snap([good, bare])))["DES-01"] == "warn"
    assert set(_by_id(checks_design.run(_snap([]))).values()) == {"warn"}


# ---------- scoring ----------


def _f(check_id, category, kind, severity):
    return Finding(check_id, category, kind, severity, "m", {})


def test_score_spec_heuristic_split():
    findings = [
        _f("PROTO-01", "protocol", "spec", "pass"),
        _f("PROTO-02", "protocol", "spec", "pass"),
        _f("PROTO-03", "protocol", "spec", "pass"),
        _f("LAT-01", "latency", "heuristic", "pass"),
        _f("LAT-02", "latency", "heuristic", "pass"),
        _f("LAT-03", "latency", "heuristic", "fail"),
        _f("SPEECH-00", "speech", "heuristic", "warn"),
    ]
    categories, total, spec, heuristic = score(findings)
    assert categories == {"protocol": 30, "latency": 10, "speech": 18, "design": 0}
    assert total == 58
    assert spec == 100
    assert heuristic == 40


def test_score_empty_and_invalid():
    assert score([]) == ({"protocol": 0, "latency": 0, "speech": 0, "design": 0}, 0, 0, 0)
    with pytest.raises(ValueError):
        score([_f("X-01", "bogus", "spec", "pass")])
    with pytest.raises(ValueError):
        score([_f("X-01", "protocol", "spec", "meh")])


# ---------- report and CLI helpers ----------


def _report(message):
    findings = [Finding("PROTO-01", "protocol", "spec", "pass", message, {"x": 1})]
    categories, total, spec, heuristic = score(findings)
    return Report(
        "http://x/mcp", "2025-11-25", findings, categories, total, spec, heuristic,
        "2026-10-06T00:00:00+00:00", "0.1.0",
    )


def test_report_to_dict_is_json_serialisable():
    data = _report("ok").to_dict()
    assert json.loads(json.dumps(data))["findings"][0]["check_id"] == "PROTO-01"


def test_html_report_escapes_and_labels_scores():
    report = _report("bad <script>alert(1)</script>")
    page = report_html.render(report, _snap([_tool()]))
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "Spec score" in page and "Heuristic score" in page
    assert page.startswith("<!doctype html>")


def test_scorecard_shows_both_scores():
    text = format_scorecard(_report("ok"), _snap())
    assert "SPEC score" in text and "HEURISTIC score" in text and "1 of 1 checks passed" in text


def test_load_probe_args(tmp_path):
    path = tmp_path / "probe.json"
    path.write_text(json.dumps({"_note": "x", "srv": {"t": {"a": 1}}}), encoding="utf-8")
    assert load_probe_args(str(path), "srv") == {"t": {"a": 1}}
    assert load_probe_args(str(path), "other") == {}
    path.write_text(json.dumps({"srv": {"t": 5}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_probe_args(str(path), "srv")
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_probe_args(str(path), "srv")


def test_redirect_target_same_host_only():
    base = "http://127.0.0.1:9101/mcp"
    assert _redirect_target(base, "http://127.0.0.1:9101/mcp/") == base + "/"
    assert _redirect_target(base, "/mcp/") == base + "/"
    assert _redirect_target(base, None) is None
    assert _redirect_target(base, "") is None
    assert _redirect_target(base, "http://evil.example/mcp/") is None
    assert _redirect_target(base, "https://127.0.0.1:9101/mcp/") is None
    assert _redirect_target(base, "ftp://127.0.0.1:9101/mcp/") is None