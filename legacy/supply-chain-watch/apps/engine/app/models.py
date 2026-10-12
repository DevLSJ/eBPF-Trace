"""engine ↔ gateway 공용 스키마 (docs/05 §2·§4). camelCase alias로 TS 타입과 통일."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

RiskLevel = Literal["HIGH", "MEDIUM", "LOW"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LlmStatus = Literal["OK", "SKIPPED_GATE", "SKIPPED_BUDGET", "REFUSED", "ERROR", "CACHED"]
Tag = Literal[
    "C2_CONNECTION", "ENV_EXFILTRATION", "CREDENTIAL_ACCESS", "OBFUSCATION",
    "INSTALL_HOOK", "DOWNLOAD_EXECUTE", "PERSISTENCE", "BACKDOOR",
    "SUPPLY_CHAIN", "EVASION", "CI_SECRET_LEAK", "CI_PRIVILEGE_ESCALATION",
    "CI_UNTRUSTED_ACTION", "NONE",
]


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class CommitMeta(CamelModel):
    repo_full_name: str
    sha: str
    branch: str | None = None
    author_login: str | None = None
    author_name: str | None = None
    message: str = ""
    committed_at: str | None = None
    stars: int | None = None
    default_branch: str | None = None


class ChangedFile(CamelModel):
    filename: str
    status: str = "modified"
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class AnalyzeOptions(CamelModel):
    force_llm: bool = False
    always_llm: bool = False
    skip_llm: bool = False
    prompt_name: str | None = None
    prompt_version: int | None = None


class AnalyzeRequest(CamelModel):
    commit: CommitMeta
    files: list[ChangedFile] = []
    diff: str = ""
    options: AnalyzeOptions = AnalyzeOptions()


class MatchedRule(CamelModel):
    rule_id: str
    category: Tag
    severity: Severity
    file: str
    snippet: str
    line_hint: str
    count: int = 1
    description_ko: str = ""


class StaticSection(CamelModel):
    score: int = 0
    level: RiskLevel = "LOW"
    matched_rules: list[MatchedRule] = []
    sensitive_files: list[str] = []
    latency_ms: int = 0


class LlmSection(CamelModel):
    status: LlmStatus = "SKIPPED_GATE"
    model: str | None = None
    prompt_version: int | None = None
    result: dict | None = None
    usage: dict | None = None
    latency_ms: int | None = None
    error: str | None = None
    # 게이트 판단 (docs/03 §4). Phase 3에서는 판단만 하고 실제 호출은 Phase 4
    gate_passed: bool = False
    gate_reasons: list[str] = []
    prompt_name: str | None = None
    # 2단계 분석 기록: [{model, status, riskScore, latencyMs, error}] (1단계 저렴한 모델 → 2단계 정밀 모델)
    stages: list[dict] = []


class PreprocessSection(CamelModel):
    truncated: bool = False
    excluded_files: list[str] = []
    analyzed_bytes: int = 0


class AnalysisResult(CamelModel):
    risk_score: int = 0
    risk_level: RiskLevel = "LOW"
    tags: list[Tag] = []
    static: StaticSection = StaticSection()
    llm: LlmSection = LlmSection()
    preprocess: PreprocessSection = PreprocessSection()
