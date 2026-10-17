# @exports: Category, Severity, Kind: Literal types
# @exports: CATEGORY_MAX: dict[str,int] = {protocol:30, latency:15, speech:35, design:20}
# @exports: Finding(check_id:str, category:Category, kind:Kind, severity:Severity, message:str, evidence:dict[str,Any]) frozen dataclass
# @exports: ToolInfo(name:str, description:str, input_schema:dict, output_schema:dict|None, annotations:dict[str,Any]) frozen dataclass
# @exports: Snapshot(url:str, negotiated_protocol:str, server_name:str, server_version:str, tools:list[ToolInfo], init_ms:float, list_tools_ms:float) frozen dataclass
# @exports: ProbeResult(tool:str, text:str, structured:dict|None, is_error:bool, latency_ms:float) frozen dataclass
# @exports: Report(url, negotiated_protocol, findings, category_scores, total, spec_score, heuristic_score, generated_at, sayable_version) dataclass with to_dict()->dict
# @exports: score(findings: Sequence[Finding]) -> tuple[dict[str,int], int, int, int]  # (category_scores, total, spec_score, heuristic_score)
# @imports: (none)
# @env: (none)
# @schema: per category: pass=1, warn=0.5, fail=0; category_score=round(MAX*earned/count); empty category=0; total=sum
# @schema: spec_score=round(100*protocol/30); heuristic_score=round(100*(latency+speech+design)/70)
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal, Sequence

Category = Literal["protocol", "latency", "speech", "design"]
Severity = Literal["pass", "warn", "fail"]
Kind = Literal["spec", "heuristic"]

CATEGORY_MAX: dict[str, int] = {"protocol": 30, "latency": 15, "speech": 35, "design": 20}

_SEVERITY_WEIGHT: dict[str, float] = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


@dataclass(frozen=True)
class Finding:
    check_id: str
    category: Category
    kind: Kind
    severity: Severity
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str
    input_schema: dict
    output_schema: dict | None
    annotations: dict[str, Any]


@dataclass(frozen=True)
class Snapshot:
    url: str
    negotiated_protocol: str
    server_name: str
    server_version: str
    tools: list[ToolInfo]
    init_ms: float
    list_tools_ms: float


@dataclass(frozen=True)
class ProbeResult:
    tool: str
    text: str
    structured: dict | None
    is_error: bool
    latency_ms: float


@dataclass
class Report:
    url: str
    negotiated_protocol: str
    findings: list[Finding]
    category_scores: dict[str, int]
    total: int
    spec_score: int
    heuristic_score: int
    generated_at: str
    sayable_version: str

    def to_dict(self) -> dict:
        return asdict(self)


def score(findings: Sequence[Finding]) -> tuple[dict[str, int], int, int, int]:
    for f in findings:
        if f.category not in CATEGORY_MAX:
            raise ValueError(
                f"finding {f.check_id} has unknown category {f.category!r}; "
                f"expected one of {sorted(CATEGORY_MAX)}"
            )
        if f.severity not in _SEVERITY_WEIGHT:
            raise ValueError(
                f"finding {f.check_id} has unknown severity {f.severity!r}; "
                f"expected one of {sorted(_SEVERITY_WEIGHT)}"
            )
    category_scores: dict[str, int] = {}
    for category, maximum in CATEGORY_MAX.items():
        group = [f for f in findings if f.category == category]
        if not group:
            category_scores[category] = 0
            continue
        earned = sum(_SEVERITY_WEIGHT[f.severity] for f in group)
        category_scores[category] = round(maximum * earned / len(group))
    total = sum(category_scores.values())
    spec_score = round(100 * category_scores["protocol"] / CATEGORY_MAX["protocol"])
    heuristic_points = (
        category_scores["latency"] + category_scores["speech"] + category_scores["design"]
    )
    heuristic_max = CATEGORY_MAX["latency"] + CATEGORY_MAX["speech"] + CATEGORY_MAX["design"]
    heuristic_score = round(100 * heuristic_points / heuristic_max)
    return category_scores, total, spec_score, heuristic_score
