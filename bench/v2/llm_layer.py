#!/usr/bin/env python3
"""평가 규칙 v2 — LLM 2차 분석 층(protocol.json layers.llm · layers.missing).

패키지 하나의 글(다른 층이 만들어 넘겨 준다)과 정적 결과 요약을 Claude 에게 보내 위험 점수를 정해진 JSON 형식으로 받고,
이어받을 수 있는 JSONL 로 남긴다. 이 파일은 표본 파일을 읽지 않는다.

  단계형 [2026-11-12 사용자 결정]: 먼저 Haiku 5.5 → 위험 점수 40 이상이거나 거부면 Opus 5.5 로 한 번 더.
  상한: 평가 1회 $100 — 다음 호출이 상한을 넘을 수 있으면 부르지 않고 SKIPPED_BUDGET 으로 남긴다.
  보내는 것: 공개 패키지의 소스 글 + 정적 결과 요약뿐(서버 · 사용자 정보 · 표본 id 없음). 주소는 공식 API 로 고정한다.
  못 한 표본(오류 · 거부 · 예산)도 줄을 남긴다 — 판정에서는 「LLM 이 못 잡음」(riskScore = null).

  ANTHROPIC_API_KEY=… bench/.venv/bin/python bench/v2/llm_layer.py run --input in.jsonl --out out.jsonl
  python3 bench/v2/llm_layer.py estimate --input in.jsonl    # 호출 없이 비용 어림(가정 포함)
  python3 bench/v2/llm_layer.py cost --out out.jsonl         # 결과 파일의 누적 비용 · 상태별 수

입력 한 줄 = {"id", "text", "static": {…}}. 결과 한 줄(키 = id)은 analyze_one 참고. 결과에는 근거 줄(악성 코드 조각)이 들어가므로
git 이 추적하지 않는 곳(bench/raw/ · bench/datasets/)에 둔다.
순수 계산(비용 · 예산 · 캐시 키 · 결과 줄 · 단계 판단)은 표준 라이브러리만 쓴다. SDK(anthropic)는 실제 호출에만 필요하다
(bench/v2/requirements-llm.txt → bench/.venv).
API 사용법 · 가격의 근거: claude-api 스킬(2026-11-03 판) + platform.claude.com 문서(2026-11-12 확인).
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys
import time

try:  # SDK 는 실제 호출(make_client)과 오류 분류에만 쓴다. 없으면 순수 계산 · 가짜 클라이언트 시험만 돈다(CI)
    import anthropic
except ImportError:
    anthropic = None

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT_PATH = os.path.join(HERE, "prompts", "package-v1.json")
OFFICIAL_BASE_URL = "https://api.anthropic.com"

STAGE1_MODEL = "claude-haiku-5-5"  # 1단계: 싸게 거른다
STAGE2_MODEL = "claude-opus-5-5"   # 2단계: 위험해 보이는 것만 정밀하게
ESCALATE_SCORE = 40                # 1단계 점수가 이 이상이면 2단계(이전 프로젝트 llm_triage_threshold 와 같다)
# effort: 두 모델 모두 기본값이 medium 이다. 기본값을 쓰되 요청에 적어 고정한다(바꾸면 캐시 키도 바뀐다).
# 생각(thinking)은 Opus 5.5 에서 끌 수 없고 Haiku 5.5 도 기본으로 켜져 있다 — adaptive 로 두고 깊이는 effort 로만 조절한다.
EFFORT = {STAGE1_MODEL: "medium", STAGE2_MODEL: "medium"}
MAX_TOKENS = 16000                 # 스킬의 권고 기본값. 생각 토큰도 여기에 든다 — 짧게 잡으면 답이 잘린다
BUDGET_USD = 100.0                 # 평가 1회 상한(protocol.json layers.llm) — 사용자 결정이라 실행 옵션으로는 낮출 수만 있다
MAX_ERRORS_IN_A_ROW = 5            # 한 모델이 이만큼 잇달아 실패하면 실행을 멈춘다(키 · 권한 · 요청 모양 문제)

# 패키지 글 상한(글자 수). 넘으면 앞부분만 보내고 truncated 를 남긴다.
# 근거 1(창에 반드시 들어간다): 글자 하나는 UTF-8 4바이트 이하이고 토큰 수는 바이트 수를 넘지 않는다고 보면(bound_input_tokens)
#   20만 자 <= 80만 토큰 — 시스템 프롬프트 · 정적 요약 · 출력 16,000 을 더해도 두 모델의 창(100만 토큰) 안이다.
# 근거 2(비용): 코드가 토큰당 3자 안팎이면 20만 자는 약 7만 토큰 — Haiku 5.5 의 높은 요금표 경계(프롬프트 10만 토큰) 아래다.
#   토큰당 글자 수는 재지 못했다(이 도구를 만들 때는 호출하지 않았다) — 첫 실행의 usage 로 확인한다. 경계를 넘은 요청은 높은 요금표로 센다.
MAX_TEXT_CHARS = 200_000
MAX_STATIC_CHARS = 4_000           # 정적 결과 요약(JSON 글) 상한
MAX_EVIDENCE = 8
FRAMING_TOKENS = 2048              # 메시지 틀 + 구조화 출력이 덧붙이는 시스템 글 몫(크기는 문서에 없다 — 도구 사용 때 붙는 글이 300~400 토큰이라 넉넉히)
COST_DIGITS = 8

# USD / 100만 토큰. 출처: https://platform.claude.com/docs/en/about-claude/pricing (2026-11-12 확인) — claude-api 스킬(2026-11-03 판)의 값과 같다.
# upTo = 그 요금표가 적용되는 프롬프트 길이 상한(입력 + 캐시 읽기 + 캐시 쓰기 토큰, None = 상한 없음).
# Haiku 5.5 는 프롬프트가 10만 토큰을 넘으면 그 요청 전체(출력 포함)에 높은 요금표가 붙는다. 캐시 쓰기는 5분 TTL 값(1.25배)만 쓴다.
# 여기에 없는 모델은 부르지 않는다(비용을 셀 수 없다). 배치(50% 할인) · 빠른 모드 값은 쓰지 않아 넣지 않았다.
PRICES = {
    "claude-haiku-5-5": [
        {"upTo": 100_000, "input": 0.10, "cacheWrite5m": 0.125, "cacheRead": 0.01, "output": 0.50},
        {"upTo": None, "input": 0.50, "cacheWrite5m": 0.625, "cacheRead": 0.05, "output": 2.50},
    ],
    "claude-opus-5-5": [
        {"upTo": None, "input": 4.00, "cacheWrite5m": 5.00, "cacheRead": 0.20, "output": 20.00},
    ],
}
# 출력 전에 거부된 요청이 청구되는 분류(문서 「How refusals are billed」, 2026-11-12 확인 · 바뀔 수 있다). 그 밖(cyber · general_harms · 분류 없음)은
# 청구되지 않는다. 상한 계산에는 보수적으로 모두 더하고, 청구되지 않는 것은 단계 기록에 billed: false 로 표시만 한다.
BILLED_REFUSALS = ("bio", "frontier_llm", "reasoning_extraction")

USAGE_KEYS = ("inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens")
DONE = ("OK", "REFUSED", "CACHED")  # 다시 돌릴 때 건너뛰는 상태. ERROR · SKIPPED_BUDGET 은 다시 해 본다

# 출력 스키마 — 이전 프로젝트(Supply Chain Watch) LlmAnalysis 그대로. API 의 구조화 출력(output_config.format)이 모양을 강제한다.
# 구조화 출력이 받지 않는 제약(숫자 범위 · 글 길이 · 배열 개수 상한)은 넣지 않고 validate_analysis 에서 본다.
LEVELS = ("HIGH", "MEDIUM", "LOW")
TAGS = (
    "C2_CONNECTION", "ENV_EXFILTRATION", "CREDENTIAL_ACCESS", "OBFUSCATION", "INSTALL_HOOK", "DOWNLOAD_EXECUTE", "PERSISTENCE",
    "BACKDOOR", "SUPPLY_CHAIN", "EVASION", "CI_SECRET_LEAK", "CI_PRIVILEGE_ESCALATION", "CI_UNTRUSTED_ACTION", "NONE",
)
EVIDENCE_KEYS = ("file", "line_hint", "reason_ko")
ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "integer", "description": "0~100 위험 점수"},
        "risk_level": {"type": "string", "enum": list(LEVELS), "description": "70 이상 HIGH, 40~69 MEDIUM, 그 아래 LOW"},
        "detected_tags": {"type": "array", "items": {"type": "string", "enum": list(TAGS)}, "description": "탐지된 위협 분류. 없으면 [\"NONE\"]"},
        "attack_narrative_ko": {"type": "string", "description": "공격자가 무엇을 어떻게 숨겼는지(정상이면 왜 정상인지) 한글 서술"},
        "evidence": {
            "type": "array",
            "description": "가장 결정적인 근거부터 최대 8개",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "근거가 있는 파일 경로"},
                    "line_hint": {"type": "string", "description": "패키지 글에 실제로 있는 줄의 일부를 그대로 옮긴 것"},
                    "reason_ko": {"type": "string", "description": "이 줄이 왜 위험한지 한글 설명"},
                },
                "required": list(EVIDENCE_KEYS),
                "additionalProperties": False,
            },
        },
        "benign_explanation_ko": {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "정상일 가능성이 있다면 그 이유, 없으면 null"},
        "confidence": {"type": "integer", "description": "판단 확신도 0~100"},
        "recommended_action_ko": {"type": "string", "description": "운영자에게 권하는 조치"},
    },
    "required": ["risk_score", "risk_level", "detected_tags", "attack_narrative_ko", "evidence", "benign_explanation_ko",
                 "confidence", "recommended_action_ko"],
    "additionalProperties": False,
}
SCHEMA_SHA256 = hashlib.sha256(json.dumps(ANALYSIS_SCHEMA, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
# 모델 구성 한 줄 — 캐시 키와 결과 줄에 들어간다. 모델 · effort · 올림 기준 · 출력 한도 · 스키마 가운데 하나라도 바뀌면 달라진다.
PIPELINE = (f"{STAGE1_MODEL}@{EFFORT[STAGE1_MODEL]}>{STAGE2_MODEL}@{EFFORT[STAGE2_MODEL]}"
            f"|escalate>={ESCALATE_SCORE}|max_tokens={MAX_TOKENS}|schema={SCHEMA_SHA256[:12]}")

# estimate 의 가정 — 재지 않은 값이다. (적게 드는 쪽, 많이 드는 쪽)
ASSUMED_CHARS_PER_TOKEN = (4.0, 2.5)
ASSUMED_OUTPUT_TOKENS = (800, 3000)  # 호출 한 번의 출력(생각 + JSON 답)


# ── 비용 · 예산(순수) ──

def rate_card(model, prompt_tokens):
    """그 모델 · 그 프롬프트 길이에 붙는 요금표. 가격을 모르는 모델이면 KeyError."""
    for card in PRICES[model]:
        if card["upTo"] is None or prompt_tokens <= card["upTo"]:
            return card
    raise KeyError(model)


def cost_usd(model, usage):
    """호출 한 번의 비용(USD, 반올림 전). usage = {"inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens"} — 응답의 usage 그대로.
    요금표는 프롬프트 길이(입력 + 캐시 읽기 + 캐시 쓰기)로 고른다."""
    card = rate_card(model, usage["inputTokens"] + usage["cacheReadTokens"] + usage["cacheWriteTokens"])
    return (usage["inputTokens"] * card["input"] + usage["cacheWriteTokens"] * card["cacheWrite5m"]
            + usage["cacheReadTokens"] * card["cacheRead"] + usage["outputTokens"] * card["output"]) / 1e6


def worst_case_usd(model, input_tokens, max_tokens=MAX_TOKENS):
    """다음 호출 한 번이 낼 수 있는 가장 큰 비용: 입력 전부를 가장 비싼 입력 값(캐시 쓰기)으로, 출력은 max_tokens 를 다 쓴다고 본다."""
    card = rate_card(model, input_tokens)
    return (input_tokens * max(card["input"], card["cacheWrite5m"]) + max_tokens * card["output"]) / 1e6


class Budget:
    """평가 1회 비용 상한. spent = 쓴 돈(다시 돌릴 때는 결과 파일에서 계산해 넘겨받는다), held = 부르는 중인 호출 몫."""

    def __init__(self, limit_usd=BUDGET_USD, spent_usd=0.0):
        self.limit, self.spent, self.held = float(limit_usd), float(spent_usd), 0.0

    def remaining(self):
        return self.limit - self.spent - self.held

    def hold(self, usd):
        """부르기 전에 가장 나쁜 경우의 비용을 잡는다. 상한을 넘으면 잡지 않고 False."""
        if usd > self.remaining() + 1e-12:
            return False
        self.held += usd
        return True

    def settle(self, held_usd, actual_usd):
        """잡아 둔 몫을 풀고 실제 비용만 남긴다."""
        self.held = max(0.0, self.held - held_usd)
        self.spent += actual_usd


def bound_input_tokens(request):
    """입력 토큰 수의 위쪽 어림 = 보낼 글(시스템 · 사용자 · 출력 스키마)의 UTF-8 바이트 수 + 틀 몫.
    근거(가정): 토큰 하나는 글의 1바이트 이상을 덮는다 → 토큰 수 <= 바이트 수. 코드는 보통 바이트의 1/3 안팎이라 크게 넉넉하다."""
    sent = [block["text"] for block in request["system"]] + [m["content"] for m in request["messages"]]
    sent.append(json.dumps(request["output_config"]["format"]["schema"], ensure_ascii=False))
    return sum(len(s.encode("utf-8")) for s in sent) + FRAMING_TOKENS


def count_request(request):
    """토큰 세기 요청 — 보낼 요청에서 max_tokens 만 뺀 것."""
    return {k: v for k, v in request.items() if k != "max_tokens"}


def counted_input_tokens(client, request):
    """SDK 의 토큰 세기(무료 · 호출 한도는 메시지와 별도)로 센 입력 토큰 수 + 여유(5% + 256 — 문서: 센 값은 어림이라 실제와 조금 다를 수 있다).
    세지 못하면 None."""
    try:
        counted = client.messages.count_tokens(**count_request(request)).input_tokens
    except Exception:  # noqa: BLE001 — 세기 실패는 「모른다」로 돌려준다(부르는 쪽이 보수적으로 건너뛴다)
        return None
    return math.ceil(counted * 1.05) + 256


def hold_for_call(budget, client, request):
    """다음 호출 몫을 예산에서 잡는다 → 잡은 금액(USD) 또는 None(상한을 넘을 수 있어 부르지 않는다).
    먼저 바이트 수 어림으로 보고, 그것으로 모자랄 때만 토큰을 세어 다시 본다 — 세기 요청은 상한 가까이에서만 나간다."""
    model, max_tokens = request["model"], request["max_tokens"]
    if budget.remaining() < worst_case_usd(model, 0, max_tokens):
        return None  # 출력 몫만으로도 넘는다 — 셀 것도 없다
    loose = worst_case_usd(model, bound_input_tokens(request), max_tokens)
    if budget.hold(loose):
        return loose
    counted = counted_input_tokens(client, request)
    if counted is not None:
        tight = worst_case_usd(model, counted, max_tokens)
        if tight < loose and budget.hold(tight):
            return tight
    return None


# ── 프롬프트 · 입력(순수) ──

_prompts = {}


def load_prompt(path=PROMPT_PATH):
    """프롬프트 파일({"name", "version", "system", "user_template"})에 파일 바이트의 sha256 을 더해 돌려준다."""
    if path not in _prompts:
        with open(path, "rb") as f:
            raw = f.read()
        data = json.loads(raw)
        missing = {"name", "version", "system", "user_template"} - set(data)
        if missing:
            raise ValueError(f"프롬프트 파일에 {sorted(missing)} 이(가) 없다: {path}")
        _prompts[path] = {**data, "sha256": hashlib.sha256(raw).hexdigest()}
    return _prompts[path]


def _encodable(text):
    """UTF-8 로 보낼 수 없는 글자(짝 없는 대리 문자)를 ? 로 바꾼다."""
    return text.encode("utf-8", "replace").decode("utf-8")


def clip(text, max_chars=MAX_TEXT_CHARS):
    """(보낼 글, 잘랐는지). 상한을 넘으면 앞부분만 남기고 끝에 원래 길이를 적는다."""
    text = _encodable(text)
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + f"\n…[절삭: 전체 {len(text):,}자 가운데 앞 {max_chars:,}자만 실었다]", True


def static_block(static_summary):
    """정적 결과 요약을 글로. 키 순서를 고정해 같은 요약이면 같은 글(같은 입력 해시)이 되게 한다."""
    if not static_summary:
        return "(없음)"
    text = _encodable(json.dumps(static_summary, ensure_ascii=False, sort_keys=True, indent=1, default=str))
    return text if len(text) <= MAX_STATIC_CHARS else text[:MAX_STATIC_CHARS] + "\n…[절삭]"


class _Blank(dict):
    def __missing__(self, key):  # 틀에 모르는 자리가 있으면 빈칸(이전 프로젝트 render 와 같다)
        return ""


_HOME = os.path.expanduser("~")


def _no_local_paths(text):
    """이 PC 의 홈 폴더 경로(사용자 이름이 든다)가 섞여 왔으면 ~ 로 바꾼다 — 다른 층이 만든 요약 · 글에 로컬 경로가 남았을 때의 안전망.
    공개 패키지의 글에는 이 경로가 있을 수 없으므로 분석할 내용은 바뀌지 않는다."""
    return text.replace(_HOME, "~") if len(_HOME) > 3 else text


def render_user(prompt, package_text, static_summary, truncated):
    """사용자 메시지 글. 패키지 글과 정적 요약뿐 — 표본 id 는 넣지 않는다."""
    return prompt["user_template"].format_map(_Blank(
        static_block=_no_local_paths(static_block(static_summary)), truncated_note=" (절삭됨)" if truncated else "",
        package_text=_no_local_paths(package_text)))


def build_request(model, prompt, user_text):
    """Messages API 요청(SDK messages.stream 의 인자 그대로).
    - 고정 시스템 프롬프트에 프롬프트 캐시(5분), 표본마다 다른 글은 user 메시지에만
    - 출력은 구조화 출력(JSON 스키마) — Opus 5.5 는 강제 도구 사용이 400 이라 이 방식으로 받는다
    - 생각은 adaptive(끄지 않는다), 깊이는 effort 로. temperature 같은 표본 추출 값은 두 모델 모두 받지 않아 보내지 않는다
    - 거부를 다른 모델로 넘기는 서버 쪽 대체(fallbacks)는 쓰지 않는다 — 평가가 모델 둘을 고정하고, Haiku 5.5 에는 대체가 없다"""
    return {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": [{"type": "text", "text": prompt["system"], "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user_text}],
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": EFFORT[model], "format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA}},
    }


def cache_key(prompt_sha, input_sha, pipeline=PIPELINE):
    """캐시 키 = sha256(모델 구성 · 프롬프트 sha · 입력 sha)."""
    return hashlib.sha256("\n".join((pipeline, prompt_sha, input_sha)).encode()).hexdigest()


# ── 응답 읽기(순수) ──

def _whole(value, low, high):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def validate_analysis(obj):
    """모델이 돌려준 JSON → (분석, None) 또는 (None, 사유). API 가 모양을 강제하지만 범위(0~100)는 걸 수 없어 여기서 본다.
    evidence 가 8개를 넘으면 앞 8개만 남긴다(개수 상한도 스키마로는 못 건다 — 값을 치른 답을 그 때문에 버리지 않는다)."""
    if not isinstance(obj, dict):
        return None, "객체가 아니다"
    wanted = set(ANALYSIS_SCHEMA["properties"])
    if set(obj) != wanted:
        return None, f"칸이 다르다(없음 {sorted(wanted - set(obj))} · 모름 {len(set(obj) - wanted)}개)"
    if not _whole(obj["risk_score"], 0, 100):
        return None, "risk_score 가 0~100 정수가 아니다"
    if obj["risk_level"] not in LEVELS:
        return None, "risk_level 이 HIGH · MEDIUM · LOW 가 아니다"
    tags = obj["detected_tags"]
    if not isinstance(tags, list) or any(not isinstance(t, str) or t not in TAGS for t in tags):
        return None, "detected_tags 에 정해진 분류가 아닌 것이 있다"
    if not _whole(obj["confidence"], 0, 100):
        return None, "confidence 가 0~100 정수가 아니다"
    if not isinstance(obj["attack_narrative_ko"], str) or not isinstance(obj["recommended_action_ko"], str):
        return None, "서술 칸이 글이 아니다"
    if obj["benign_explanation_ko"] is not None and not isinstance(obj["benign_explanation_ko"], str):
        return None, "benign_explanation_ko 가 글도 null 도 아니다"
    evidence = obj["evidence"]
    if not isinstance(evidence, list) or any(
            not isinstance(e, dict) or set(e) != set(EVIDENCE_KEYS) or any(not isinstance(v, str) for v in e.values()) for e in evidence):
        return None, "evidence 모양이 다르다"
    return {**obj, "evidence": evidence[:MAX_EVIDENCE]}, None


def _long_fields(analysis):
    """결과 줄의 analysis 칸(긴 글) — 키는 이 저장소의 JSON 방식(camelCase)으로."""
    return {
        "riskLevel": analysis["risk_level"],
        "attackNarrativeKo": analysis["attack_narrative_ko"],
        "evidence": [{"file": e["file"], "lineHint": e["line_hint"], "reasonKo": e["reason_ko"]} for e in analysis["evidence"]],
        "benignExplanationKo": analysis["benign_explanation_ko"],
        "recommendedActionKo": analysis["recommended_action_ko"],
    }


def _ms(started):
    return round((time.monotonic() - started) * 1000)


def _stage(model, status, *, usage=None, score=None, error=None, ms=0):
    usage = usage or dict.fromkeys(USAGE_KEYS, 0)
    return {"model": model, "status": status, "riskScore": score, **usage,
            "costUsd": round(cost_usd(model, usage), COST_DIGITS), "ms": ms, "error": error}


def read_usage(message):
    """응답의 usage → 토큰 4종. 없는 칸은 0."""
    usage = getattr(message, "usage", None)
    names = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    return {key: int(getattr(usage, name, 0) or 0) for key, name in zip(USAGE_KEYS, names)}


def read_message(model, message):
    """SDK 가 모아 준 최종 메시지 → (단계 기록, 분석 또는 None). 블록은 자리 말고 종류로 찾는다(앞에 생각 블록이 온다)."""
    usage = read_usage(message)
    content = list(getattr(message, "content", None) or [])
    stop = getattr(message, "stop_reason", None)
    if stop == "refusal":  # 분기는 stop_reason 으로만 — stop_details 는 참고용이고 None 일 수 있다
        category = getattr(getattr(message, "stop_details", None), "category", None)
        stage = _stage(model, "REFUSED", usage=usage, error=f"refusal:{category or 'unknown'}")
        if not content and usage["outputTokens"] == 0 and category not in BILLED_REFUSALS:
            stage["billed"] = False  # 출력 전 거부 · 청구되지 않는 분류(상한 계산에는 그대로 더한다)
        return stage, None
    if stop == "max_tokens":
        return _stage(model, "ERROR", usage=usage, error=f"max_tokens: 출력이 {MAX_TOKENS} 토큰에서 잘렸다"), None
    text = next((block.text for block in content if getattr(block, "type", None) == "text"), None)
    if text is None:
        return _stage(model, "ERROR", usage=usage, error=f"글 블록 없음(stop={stop})"), None
    try:
        obj = json.loads(text)
    except ValueError:
        return _stage(model, "ERROR", usage=usage, error="스키마 오류: JSON 이 아니다"), None
    analysis, why = validate_analysis(obj)
    if analysis is None:
        return _stage(model, "ERROR", usage=usage, error=f"스키마 오류: {why}"), None
    return _stage(model, "OK", usage=usage, score=analysis["risk_score"]), analysis


_KEY_SHAPE = re.compile(r"sk-ant-[A-Za-z0-9_\-]+")


def scrub(text):
    """글에서 API 키를 지운다(환경 변수의 값 그대로 + 키 모양). 오류 글을 결과 · 화면에 남기기 전에 거친다."""
    secret = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if len(secret) >= 8:
        text = text.replace(secret, "***")
    return _KEY_SHAPE.sub("***", text)


def describe_error(exc):
    """호출 오류를 짧은 글로: 종류 · 상태 코드 · 서버가 준 사유 앞부분(키는 지운다). 요청 본문은 남기지 않는다."""
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):  # anthropic.APIStatusError 계열(BadRequestError · RateLimitError · …)
        detail = scrub(str(getattr(exc, "message", "") or ""))[:200]
        return f"api {status} {name}" + (f": {detail}" if detail else "")
    if anthropic is not None and isinstance(exc, anthropic.APIConnectionError):  # 타임아웃 포함 — SDK 가 다시 해 본 뒤
        return f"connection {name}"
    return f"unexpected {name}"


# ── 호출 ──

def make_client(api_key, *, base_url=OFFICIAL_BASE_URL):
    """공식 SDK 클라이언트. 주소를 공식 API 로 적어 넘긴다 — 환경 변수 ANTHROPIC_BASE_URL(중계 서버)이 있어도 따르지 않는다.
    429 · 5xx · 연결 오류는 SDK 가 두 번 다시 해 본다. base_url 인자는 시험(이 PC 의 가짜 서버)용이다."""
    if anthropic is None:
        raise RuntimeError("anthropic SDK 가 없다 — bench/.venv 에 bench/v2/requirements-llm.txt 를 설치한다")
    return anthropic.Anthropic(api_key=api_key, base_url=base_url, max_retries=2, timeout=600.0)


def call_model(client, request):
    """모델을 한 번 부른다 → (단계 기록, 분석 또는 None). 호출 오류는 던지지 않고 ERROR 단계로 돌려준다.
    입력이 길어 스트리밍으로 받고(연결이 오래 조용하면 끊길 수 있다) SDK 가 모아 준 최종 메시지만 쓴다."""
    started = time.monotonic()
    try:
        with client.messages.stream(**request) as stream:
            message = stream.get_final_message()
    except Exception as exc:  # noqa: BLE001 — 표본 하나의 실패로 실행 전체가 죽지 않게. 잇단 실패는 run_batch 가 끊는다
        stage = _stage(request["model"], "ERROR", error=describe_error(exc), ms=_ms(started))
        if not isinstance(getattr(exc, "status_code", None), int):
            stage["costUnknown"] = True  # 상태 코드 없이 끊겼다 — 서버가 일부 처리해 청구했을 수 있으나 usage 를 받지 못했다
        return stage, None
    stage, analysis = read_message(request["model"], message)
    stage["ms"] = _ms(started)
    return stage, analysis


def run_stage(client, budget, model, prompt, user_text):
    """예산을 잡고 한 단계를 부른다 → (단계 기록, 분석 또는 None). 상한을 넘을 수 있으면 부르지 않는다(SKIPPED_BUDGET)."""
    request = build_request(model, prompt, user_text)
    held = hold_for_call(budget, client, request)
    if held is None:
        return _stage(model, "SKIPPED_BUDGET", error=f"상한 ${budget.limit:g} 을 넘을 수 있어 부르지 않았다"), None
    stage = None
    try:
        stage, analysis = call_model(client, request)
    finally:
        budget.settle(held, stage["costUsd"] if stage else 0.0)
    return stage, analysis


def should_escalate(stage):
    """1단계가 거부했거나 위험 점수가 ESCALATE_SCORE 이상이면 2단계로. 1단계 오류는 올리지 않는다."""
    return stage["status"] == "REFUSED" or (stage["status"] == "OK" and stage["riskScore"] >= ESCALATE_SCORE)


def analyze_one(sample_id, package_text, static_summary, *, client, budget, cache, prompt=None, max_chars=MAX_TEXT_CHARS):
    """표본 하나를 분석해 결과 줄(dict)을 돌려준다. 호출 오류로 던지지 않는다.

    client = SDK 클라이언트(make_client) · budget = Budget · cache = {캐시 키: 결과 줄} 또는 None(끔).
    같은 키의 OK 결과가 cache 에 있으면 부르지 않고(status CACHED · 비용 0), 새 OK 결과는 cache 에 더한다.

    결과 줄: id · status(OK | REFUSED | ERROR | SKIPPED_BUDGET | CACHED) · riskScore(없으면 None) · tags · confidence ·
    model(최종 판단을 낸 모델) · stages[{model · status · riskScore · inputTokens · outputTokens · cacheReadTokens · cacheWriteTokens ·
    costUsd · ms · error}] · costUsd(단계 합) · promptSha256 · inputSha256 · ms · error · analysis(등급 · 서술 · 근거 같은 긴 칸) ·
    truncated · inputChars · cacheKey · pipeline. 2단계가 실패 · 거부 · 예산 초과면 1단계 결과를 쓴다(단계 기록에는 남는다)."""
    started = time.monotonic()
    prompt = prompt or load_prompt()
    text, truncated = clip(package_text, max_chars)
    user_text = render_user(prompt, text, static_summary, truncated)
    input_sha = hashlib.sha256(user_text.encode("utf-8")).hexdigest()
    key = cache_key(prompt["sha256"], input_sha)
    row = {
        "id": sample_id, "status": None, "riskScore": None, "tags": [], "confidence": None, "model": None, "stages": [], "costUsd": 0.0,
        "promptSha256": prompt["sha256"], "inputSha256": input_sha, "ms": 0, "error": None, "analysis": None,
        "truncated": truncated, "inputChars": len(package_text), "cacheKey": key, "pipeline": PIPELINE,
    }

    hit = cache.get(key) if cache is not None else None
    if hit is not None:
        row.update(status="CACHED", riskScore=hit["riskScore"], tags=hit.get("tags") or [], confidence=hit.get("confidence"),
                   model=hit.get("model"), analysis=hit.get("analysis"), cachedFrom=hit.get("cachedFrom") or hit["id"], ms=_ms(started))
        return row

    best, analysis = run_stage(client, budget, STAGE1_MODEL, prompt, user_text)
    row["stages"].append(best)
    if should_escalate(best):
        second, second_analysis = run_stage(client, budget, STAGE2_MODEL, prompt, user_text)
        row["stages"].append(second)
        if second["status"] == "OK":
            best, analysis = second, second_analysis
    row.update(status=best["status"], error=best["error"], ms=_ms(started),
               model=None if best["status"] == "SKIPPED_BUDGET" else best["model"],
               costUsd=round(math.fsum(s["costUsd"] for s in row["stages"]), COST_DIGITS))
    if best["status"] == "OK":
        row.update(riskScore=analysis["risk_score"], tags=analysis["detected_tags"], confidence=analysis["confidence"],
                   analysis=_long_fields(analysis))
        if cache is not None:
            cache[key] = row
    return row


# ── 결과 파일 · 실행 ──

class Results:
    """결과 파일(JSONL, 키 = id). 덧붙이기만 한다 — 같은 id 는 마지막 줄이 유효하고(rows), 누적 비용(spent)은 모든 줄을 더한다
    (다시 해서 덮인 줄에 쓴 돈도 쓴 돈이다). 중단 뒤 다시 열면 누적 비용과 끝난 표본이 그대로 돌아온다."""

    def __init__(self, path):
        self.path, self.rows, self.lines, self.torn = path, {}, [], 0
        self._unfinished_line = False
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    self._unfinished_line = not line.endswith("\n")
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                        self.rows[row["id"]] = row
                    except (ValueError, KeyError, TypeError):
                        self.torn += 1  # 쓰다 끊긴 줄 — 그 호출의 비용은 알 수 없다
                        continue
                    self.lines.append(row)
        self.spent = math.fsum(row.get("costUsd") or 0.0 for row in self.lines)

    def add(self, row):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        # errors="replace": 모델 답에 인코딩할 수 없는 글자가 섞여도 값을 치른 결과 줄은 남긴다
        with open(self.path, "a", encoding="utf-8", errors="replace") as f:
            if self._unfinished_line:  # 끊긴 줄 뒤에 바로 붙으면 새 줄까지 못 읽게 된다
                f.write("\n")
                self._unfinished_line = False
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.rows[row["id"]] = row
        self.lines.append(row)
        self.spent += row.get("costUsd") or 0.0

    def done(self, sample_id):
        row = self.rows.get(sample_id)
        return row is not None and row.get("status") in DONE

    def cache(self):
        """캐시 색인 {캐시 키: 결과 줄} — 점수가 있는 줄(OK, 그리고 OK 를 옮겨 적은 CACHED)만."""
        return {r["cacheKey"]: r for r in self.rows.values() if r.get("status") in ("OK", "CACHED") and r.get("cacheKey")}


def read_input(path):
    """입력 JSONL 을 한 줄씩. 한 줄 = {"id": 글, "text": 글, "static": {…}(없어도 된다)}. 모양이 다르면 ValueError(몇째 줄인지)."""
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                raise ValueError(f"{path} {number}번째 줄: JSON 이 아니다") from None
            static = row.get("static") if isinstance(row, dict) else None
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]
                    or not isinstance(row.get("text"), str) or not isinstance(static or {}, dict)):
                raise ValueError(f'{path} {number}번째 줄: {{"id": 글, "text": 글, "static": {{…}}}} 모양이 아니다')
            yield {"id": row["id"], "text": row["text"], "static": static or {}}


def run_batch(samples, *, results, client, budget, cache, prompt, max_chars=MAX_TEXT_CHARS, limit=None,
              max_errors=MAX_ERRORS_IN_A_ROW, progress=None):
    """표본을 차례로 분석해 결과 파일에 덧붙인다. 끝난 id(OK · REFUSED · CACHED)는 건너뛰고 ERROR · SKIPPED_BUDGET 은 다시 해 본다.
    한 모델이 max_errors 번 잇달아 실패하면 멈춘다 — 2단계가 계속 실패하는데 1단계 결과만으로 끝까지 가는 일을 막는다.
    → {"made": 새로 쓴 줄 수, "stopped": 멈춘 사유 또는 None, "failing": 잇달아 실패한 모델 또는 None}"""
    made, streak, stopped, failing = 0, {}, None, None
    for sample in samples:
        sample_id = sample["id"]
        if results.done(sample_id):
            continue
        if limit is not None and made >= limit:
            stopped = f"--limit {limit}"
            break
        row = analyze_one(sample_id, sample["text"], sample.get("static") or {}, client=client, budget=budget, cache=cache,
                          prompt=prompt, max_chars=max_chars)
        before = results.rows.get(sample_id)
        if not (row["status"] == "SKIPPED_BUDGET" and before is not None and before.get("status") == "SKIPPED_BUDGET"):
            results.add(row)  # 예산이 그대로면 같은 건너뜀 줄을 돌릴 때마다 또 쓰지 않는다
            made += 1
        for stage in row["stages"]:
            if stage["status"] == "ERROR":
                streak[stage["model"]] = streak.get(stage["model"], 0) + 1
            elif stage["status"] in ("OK", "REFUSED"):
                streak[stage["model"]] = 0
        failing = next((model for model, count in streak.items() if count >= max_errors), None)
        if failing:
            stopped = f"{failing} 이(가) {max_errors}번 잇달아 실패"
            break
        if progress:
            progress()
    return {"made": made, "stopped": stopped, "failing": failing}


def summarize(results):
    """결과 파일 요약: 상태별 수(id 마다 마지막 줄) · 누적 비용 · 모델별 호출 수 · 토큰(모든 줄)."""
    status, calls, tokens = {}, {}, dict.fromkeys(USAGE_KEYS, 0)
    unbilled, unknown = [], 0
    for row in results.rows.values():
        status[row.get("status")] = status.get(row.get("status"), 0) + 1
    for row in results.lines:
        for stage in row.get("stages") or []:
            if stage["status"] == "SKIPPED_BUDGET":
                continue
            calls[stage["model"]] = calls.get(stage["model"], 0) + 1
            for key in USAGE_KEYS:
                tokens[key] += stage.get(key) or 0
            if stage.get("billed") is False:
                unbilled.append(stage["costUsd"])
            unknown += 1 if stage.get("costUnknown") else 0
    return {
        "rows": len(results.rows), "status": dict(sorted(status.items())),
        "spentUsd": round(results.spent, COST_DIGITS), "budgetUsd": BUDGET_USD,
        # 상한 계산에는 들어갔지만 문서 기준으로는 청구되지 않는 출력 전 거부 몫 — 실제 청구는 이만큼 적을 수 있다
        "unbilledRefusalUsd": round(math.fsum(unbilled), COST_DIGITS),
        # usage 없이 끊긴 호출 수 — 0 으로 적혔지만 청구됐을 수 있다. Console 의 청구액과 맞춰 본다
        "callsWithUnknownCost": unknown,
        "calls": dict(sorted(calls.items())), "tokens": tokens, "tornLines": results.torn,
    }


def estimate(samples, prompt, *, max_chars=MAX_TEXT_CHARS, escalate=0.5):
    """호출 없이 비용 범위를 어림한다. 글자 → 토큰 비율 · 호출당 출력 토큰 · 2단계로 올라가는 비율은 가정이다(재지 않았다) —
    적은 표본으로 먼저 돌린 뒤 `cost` 의 실제 값으로 바꿔 본다. 같은 입력은 한 번만 센다(캐시)."""
    seen, sizes, total, truncated = set(), [], 0, 0
    stage1, stage2 = [0.0, 0.0], [0.0, 0.0]
    for sample in samples:
        total += 1
        text, cut = clip(sample["text"], max_chars)
        truncated += 1 if cut else 0
        user_text = render_user(prompt, text, sample["static"], cut)
        digest = hashlib.sha256(user_text.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        size = len(prompt["system"]) + len(user_text)
        sizes.append(size)
        for side, (per_token, output) in enumerate(zip(ASSUMED_CHARS_PER_TOKEN, ASSUMED_OUTPUT_TOKENS)):
            usage = {"inputTokens": math.ceil(size / per_token), "outputTokens": output, "cacheReadTokens": 0, "cacheWriteTokens": 0}
            stage1[side] += cost_usd(STAGE1_MODEL, usage)
            stage2[side] += escalate * cost_usd(STAGE2_MODEL, usage)
    return {
        "samples": total, "uniqueInputs": len(seen), "truncated": truncated,
        "chars": {"total": sum(sizes), "mean": round(sum(sizes) / len(sizes)) if sizes else 0, "max": max(sizes, default=0)},
        "usd": {"low": round(stage1[0] + stage2[0], 4), "high": round(stage1[1] + stage2[1], 4)},
        "stage1Usd": {"low": round(stage1[0], 4), "high": round(stage1[1], 4)},
        "stage2Usd": {"low": round(stage2[0], 4), "high": round(stage2[1], 4)},
        "budgetUsd": BUDGET_USD,
        "assumptions": {
            "charsPerToken": list(ASSUMED_CHARS_PER_TOKEN), "outputTokensPerCall": list(ASSUMED_OUTPUT_TOKENS), "escalateFraction": escalate,
            "note": "가정은 재지 않은 값이다. 적은 표본으로 먼저 돌려 cost 의 실제 값으로 바꿔 본다. 캐시 읽기 할인은 넣지 않았다",
        },
    }


def _status_line(results, budget, total):
    counts = {}
    for row in results.rows.values():
        counts[row.get("status")] = counts.get(row.get("status"), 0) + 1
    parts = " · ".join(f"{name} {count}" for name, count in sorted(counts.items()))
    return f"결과 {len(results.rows):,}건(입력 {total:,}줄) · {parts or '아직 없음'} · 누적 ${budget.spent:.4f} / 상한 ${budget.limit:g}"


def cmd_run(args):
    key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if not key:
        print("ANTHROPIC_API_KEY 가 없다 — 실행하지 않는다(키는 환경 변수로만 받는다)", file=sys.stderr)
        return 2
    if args.budget > BUDGET_USD:
        raise ValueError(f"상한 ${BUDGET_USD:g} 은 사용자 결정이다 — --budget 으로는 낮출 수만 있다")
    prompt = load_prompt(args.prompt)
    total = sum(1 for _ in read_input(args.input))  # 부르기 전에 입력 전체의 모양부터 본다
    results = Results(args.out)
    budget = Budget(args.budget, results.spent)
    if results.torn:
        print(f"주의: 결과 파일에 읽지 못한 줄 {results.torn}개 — 그 호출의 비용은 누적에 없다", file=sys.stderr)
    cache = None if args.no_cache else results.cache()
    client = make_client(key)
    seen = [0]

    def progress():
        seen[0] += 1
        if seen[0] % 25 == 0:  # 화면에는 수와 비용만 — 표본 id · 점수는 내지 않는다
            print(_status_line(results, budget, total), file=sys.stderr)

    done = run_batch(read_input(args.input), results=results, client=client, budget=budget, cache=cache, prompt=prompt,
                     max_chars=args.max_chars, limit=args.limit, progress=progress)
    print(_status_line(results, budget, total), file=sys.stderr)
    if done["failing"]:
        print(f"멈췄다: {done['stopped']} — 결과 파일의 error 를 보고 고친 뒤 다시 돌리면 이어서 한다", file=sys.stderr)
        return 3
    return 0


def cmd_estimate(args):
    report = estimate(read_input(args.input), load_prompt(args.prompt), max_chars=args.max_chars, escalate=args.escalate)
    print(json.dumps(report, ensure_ascii=False, indent=1))
    return 0


def cmd_cost(args):
    print(json.dumps(summarize(Results(args.out)), ensure_ascii=False, indent=1))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="평가 규칙 v2 — LLM 2차 분석 층")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="입력 JSONL 을 분석해 결과 JSONL 에 덧붙인다(다시 돌리면 이어서)")
    run.add_argument("--input", required=True, help='한 줄 = {"id", "text", "static": {…}}')
    run.add_argument("--out", required=True, help="결과 JSONL(누적 비용 · 이어받기 · 캐시의 근거)")
    run.add_argument("--budget", type=float, default=BUDGET_USD, help=f"비용 상한 USD(기본 · 최대 {BUDGET_USD:g})")
    run.add_argument("--no-cache", action="store_true", help="같은 입력도 다시 부른다(최종 측정용)")
    run.add_argument("--limit", type=int, help="새로 쓰는 줄 수 상한(적은 표본으로 먼저 돌려 볼 때)")
    run.set_defaults(fn=cmd_run)
    est = sub.add_parser("estimate", help="호출 없이 비용 범위를 어림한다")
    est.add_argument("--input", required=True)
    est.add_argument("--escalate", type=float, default=0.5, help="2단계로 올라간다고 보는 비율(가정, 기본 0.5)")
    est.set_defaults(fn=cmd_estimate)
    cost = sub.add_parser("cost", help="결과 파일의 누적 비용 · 상태별 수")
    cost.add_argument("--out", required=True)
    cost.set_defaults(fn=cmd_cost)
    for p in (run, est):
        p.add_argument("--prompt", default=PROMPT_PATH, help="프롬프트 파일")
        p.add_argument("--max-chars", type=int, default=MAX_TEXT_CHARS, help="패키지 글 상한(글자 수)")
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, RuntimeError, OSError) as e:
        print(f"오류: {scrub(str(e))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
