"""LLM 출력 스키마 (docs/03 §5.3). 모델에는 snake_case 스키마를 주고, 결과는 camelCase로 내보낸다(TS LlmAnalysis)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

LlmTag = Literal[
    "C2_CONNECTION", "ENV_EXFILTRATION", "CREDENTIAL_ACCESS", "OBFUSCATION",
    "INSTALL_HOOK", "DOWNLOAD_EXECUTE", "PERSISTENCE", "BACKDOOR",
    "SUPPLY_CHAIN", "EVASION", "CI_SECRET_LEAK", "CI_PRIVILEGE_ESCALATION",
    "CI_UNTRUSTED_ACTION", "NONE",
]


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class Evidence(_Base):
    file: str = Field(description="근거가 있는 파일 경로")
    line_hint: str = Field(description="Diff에 실제로 있는 줄의 일부를 그대로 옮긴 것")
    reason_ko: str = Field(description="이 줄이 왜 위험한지 한글 설명")


class LlmAnalysis(_Base):
    risk_score: int = Field(ge=0, le=100, description="0~100 위험 점수")
    risk_level: Literal["HIGH", "MEDIUM", "LOW"] = Field(description="70 이상 HIGH, 40~69 MEDIUM, 그 아래 LOW")
    detected_tags: list[LlmTag] = Field(description="탐지된 위협 분류. 없으면 [\"NONE\"]")
    attack_narrative_ko: str = Field(description="공격자가 무엇을 어떻게 숨겼는지(정상이면 왜 정상인지) 한글 서술")
    evidence: list[Evidence] = Field(max_length=8, description="가장 결정적인 근거부터 최대 8개")
    benign_explanation_ko: str | None = Field(default=None, description="정상일 가능성이 있다면 그 이유")
    confidence: int = Field(ge=0, le=100, description="판단 확신도 0~100")
    recommended_action_ko: str = Field(description="운영자에게 권하는 조치")


def tool_schema() -> dict:
    """report_analysis 도구 입력 스키마 — 필드 이름은 snake_case 그대로."""
    return LlmAnalysis.model_json_schema(by_alias=False)
