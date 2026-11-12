package chat

import (
	"context"
	"strings"
	"testing"
)

// 화면에 보이는 챗봇 글자(11/09 사용자 결정 「— 표기 없앰」) — 답 · 사실 문장 · 시스템 프롬프트
const dash = '\u2014'

// 서버가 실제로 흘리는 답(Ollama · 도구 없이 바로 답한 경우)에도 「—」가 없다
func TestAnswerHasNoEmDash(t *testing.T) {
	f := newFakeOllama(t)
	f.answer = "- [격리] no-shell-download 위반 — 컨테이너 종료됨\n- 원인 — 설치 스크립트 —"
	s := newTestService(t, f, nil)
	rec := ask(t, s, Request{Question: "판정 대기 요약해 줘"})
	if got, want := rec.text(), "- [격리] no-shell-download 위반, 컨테이너 종료됨\n- 원인, 설치 스크립트"; got != want {
		t.Fatalf("answer %q, want %q", got, want)
	}

	f2 := newFakeOllama(t)
	f2.toolText = "SupplyGuard 는 설치 · 실행을 감시합니다 — 위반이면 격리합니다."
	rec = ask(t, newTestService(t, f2, nil), Request{Question: "안녕"})
	if got, want := rec.text(), "SupplyGuard 는 설치 · 실행을 감시합니다, 위반이면 격리합니다."; got != want {
		t.Fatalf("direct answer %q, want %q", got, want)
	}
}

// 시스템 프롬프트: 사용자가 정한 두 줄은 글자 그대로, 긴 대시 금지 · 「[상태어] 설명」 양식 줄이 있다
func TestSystemPromptDashRule(t *testing.T) {
	for _, line := range []string{
		"- 개조식 표기 시: 모든 문장은 동사로 끝내지 말고 '~함', '~됨', '~ 분석됨'과 같은 개조식 명사형으로 종결하세요.",
		"- 서술형 표기 시: 격식 있는 비즈니스 어조(~입니다, ~로 확인됩니다)를 사용하되, 감정 표현을 생략하고 객관적인 사실만 기술하세요.",
		"- 긴 대시(" + string(dash) + ")는 쓰지 않는다.",
		"「[상태어] 짧은 설명」",
	} {
		if !strings.Contains(systemPrompt, line) {
			t.Errorf("system prompt lacks %q", line)
		}
	}
	if !strings.HasPrefix(pickPrompt, systemPrompt) {
		t.Error("pick prompt must start with the system prompt")
	}
}

// 사실 문장(모델이 꺼지면 답 대신 화면에 보임): 위반 예시 · 위협 줄에 「—」 대신 쉼표 · 괄호
func TestFactSentencesNoEmDash(t *testing.T) {
	s := newTestService(t, newFakeOllama(t), nil)
	ctx := context.Background()
	f, _, err := s.RunTool(ctx, ToolAudit, map[string]string{"container": "sg-install-pip-a1"})
	if err != nil {
		t.Fatal(err)
	}
	if all := joined(f); !strings.Contains(all, ", 정책 no-shell-download, 사유 「셸 다운로드」") || strings.ContainsRune(all, dash) {
		t.Errorf("audit sentences:\n%s", all)
	}
	f, _, err = s.RunTool(ctx, ToolLatestScan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if all := joined(f); !strings.Contains(all, "위협 1: exec-base64(setup.py:12)") || strings.ContainsRune(all, dash) {
		t.Errorf("scan sentences:\n%s", all)
	}
}
