"""LLM 호출 (docs/03 §5.1~5.2). Provider 교체 지점은 이 파일 1곳.

중계 서버(국민대 new-api → Bedrock) 제약: output_config.format·tool strict·server fallbacks는 400 → JSON은 강제 tool use.
Opus 5는 생각(thinking)이 기본으로 켜져 있어 강제 tool use와 함께 쓰려면 effort high 이하에서 thinking을 끈다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

import anthropic
from pydantic import ValidationError

from app.config import settings
from app.llm.schema import LlmAnalysis, tool_schema

TOOL_NAME = "report_analysis"
MAX_TOKENS = 4096


@dataclass
class LlmCallResult:
    status: str  # OK | REFUSED | ERROR
    model: str
    analysis: LlmAnalysis | None = None
    usage: dict = field(default_factory=lambda: {"inputTokens": 0, "outputTokens": 0, "cacheReadTokens": 0})
    latency_ms: int = 0
    error: str | None = None


class LlmProvider(Protocol):
    async def analyze(self, system: str, user: str, model: str) -> LlmCallResult: ...


def _add_usage(total: dict, u) -> None:  # noqa: ANN001 — SDK Usage
    total["inputTokens"] += u.input_tokens or 0
    total["outputTokens"] += u.output_tokens or 0
    total["cacheReadTokens"] += getattr(u, "cache_read_input_tokens", 0) or 0


class AnthropicProvider:
    def __init__(self) -> None:
        # 키·주소는 설정(.env)에서만 — 코드에 문자열로 두지 않는다
        self.client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
            timeout=settings.llm_timeout_s,
            max_retries=2,
        )

    def _params(self, model: str) -> dict:
        extra: dict = {}
        if model.startswith("claude-opus-5"):
            extra["output_config"] = {"effort": settings.llm_effort}
            extra["thinking"] = {"type": "disabled"}  # 강제 tool use와 함께 쓰기 위함 (effort high 이하에서만 허용)
        return extra

    async def analyze(self, system: str, user: str, model: str) -> LlmCallResult:
        t0 = time.perf_counter()
        usage = {"inputTokens": 0, "outputTokens": 0, "cacheReadTokens": 0}
        messages: list[dict] = [{"role": "user", "content": user}]
        kwargs = dict(
            model=model,
            max_tokens=MAX_TOKENS,
            # 고정 시스템 프롬프트는 캐시, 커밋별 가변 데이터는 user 메시지에만
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=[{"name": TOOL_NAME, "description": "분석 결과를 정해진 형식으로 보고한다", "input_schema": tool_schema()}],
            tool_choice={"type": "tool", "name": TOOL_NAME},
            **self._params(model),
        )
        try:
            for attempt in range(2):  # 스키마 검증 실패 시 오류를 알려 1회 재요청
                resp = await self.client.messages.create(messages=messages, **kwargs)
                _add_usage(usage, resp.usage)
                if resp.stop_reason == "refusal":
                    cat = getattr(getattr(resp, "stop_details", None), "category", None)
                    return LlmCallResult("REFUSED", model, usage=usage, latency_ms=_ms(t0), error=f"refusal:{cat}")
                block = next((b for b in resp.content if b.type == "tool_use" and b.name == TOOL_NAME), None)
                if block is None:
                    return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error=f"도구 호출 없음(stop={resp.stop_reason})")
                try:
                    analysis = LlmAnalysis.model_validate(block.input)
                    return LlmCallResult("OK", model, analysis=analysis, usage=usage, latency_ms=_ms(t0))
                except ValidationError as e:
                    if attempt == 1:
                        return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error=f"스키마 오류: {e.errors()[:2]}")
                    messages += [
                        {"role": "assistant", "content": resp.content},
                        {"role": "user", "content": [{
                            "type": "tool_result", "tool_use_id": block.id, "is_error": True,
                            "content": f"스키마 검증 실패: {e}. 형식을 고쳐 report_analysis로 다시 보고하세요.",
                        }]},
                    ]
        except anthropic.RateLimitError as e:
            return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error=f"rate_limited: {e.status_code}")
        except anthropic.APIStatusError as e:
            return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error=f"api {e.status_code}: {str(e.message)[:160]}")
        except anthropic.APIConnectionError as e:  # 타임아웃 포함, SDK가 2회 재시도한 뒤
            return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error=f"connection: {type(e).__name__}")
        return LlmCallResult("ERROR", model, usage=usage, latency_ms=_ms(t0), error="unreachable")


def _ms(t0: float) -> int:
    return round((time.perf_counter() - t0) * 1000)


_provider: LlmProvider | None = None


def get_provider() -> LlmProvider:
    global _provider
    if _provider is None:
        _provider = AnthropicProvider()
    return _provider


def set_provider(p: LlmProvider | None) -> None:
    """테스트에서 가짜 provider 주입."""
    global _provider
    _provider = p
