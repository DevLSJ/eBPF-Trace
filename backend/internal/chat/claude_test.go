package chat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- 가짜 Claude: POST /v1/messages. stream:false 는 JSON 메시지, stream:true 는 SSE(message_start … message_stop) ---

type claudeReq struct {
	Model     string            `json:"model"`
	MaxTokens int               `json:"max_tokens"`
	Stream    bool              `json:"stream"`
	System    []json.RawMessage `json:"system"`
	Messages  []struct {
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Name        string         `json:"name"`
		InputSchema map[string]any `json:"input_schema"`
	} `json:"tools"`
	OutputConfig map[string]any `json:"output_config"`
	Thinking     map[string]any `json:"thinking"`
	Fallbacks    any            `json:"fallbacks"`
	Temperature  *float64       `json:"temperature"`

	key, beta string // 헤더 x-api-key(또는 Authorization: Bearer) · anthropic-beta
}

func (r claudeReq) systemText() string {
	var b strings.Builder
	for _, s := range r.System {
		var x struct{ Text string }
		_ = json.Unmarshal(s, &x)
		b.WriteString(x.Text)
	}
	return b.String()
}

type fakeClaude struct {
	*httptest.Server
	mu       sync.Mutex
	reqs     []claudeReq
	answer   string         // 스트리밍 답
	toolName string         // 도구 고르기(stream:false) 응답의 tool_use 이름 — 비면 text 만
	toolArgs map[string]any // tool_use input
	toolText string         // 도구 없이 답할 때 text
	status   int            // >0 이면 이 상태 코드로 오류 응답
	refuse   bool           // stop_reason: refusal (내용 없음)
}

func newFakeClaude(t *testing.T) *fakeClaude {
	f := &fakeClaude{answer: "판정 대기 건은 두 개입니다. 각 건을 열어 공격 체인을 보세요."}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeClaude) requests() []claudeReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]claudeReq(nil), f.reqs...)
}

func (f *fakeClaude) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
		http.NotFound(w, r)
		return
	}
	var req claudeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	req.key = r.Header.Get("x-api-key")
	if a := r.Header.Get("Authorization"); req.key == "" && strings.HasPrefix(a, "Bearer ") {
		req.key = strings.TrimPrefix(a, "Bearer ") // SDK v2 는 키를 Bearer 로 보낸다
	}
	req.beta = strings.Join(r.Header.Values("anthropic-beta"), ",")
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if f.status > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":"api_error","message":"fake %d"}}`, f.status)
		return
	}
	stop := "end_turn"
	if f.refuse {
		stop = "refusal"
	}
	if !req.Stream {
		content := []any{}
		if f.toolText != "" {
			content = append(content, map[string]any{"type": "text", "text": f.toolText})
		}
		if f.toolName != "" && !f.refuse {
			args := f.toolArgs
			if args == nil {
				args = map[string]any{}
			}
			content = append(content, map[string]any{"type": "tool_use", "id": "toolu_1", "name": f.toolName, "input": args})
			stop = "tool_use"
		}
		if f.refuse {
			content = []any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant", "model": req.Model, "content": content,
			"stop_reason": stop, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fl := w.(http.Flusher)
	send := func(event string, data any) {
		b, _ := json.Marshal(data)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		fl.Flush()
	}
	send("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": "msg_2", "type": "message", "role": "assistant", "model": req.Model, "content": []any{},
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 10, "output_tokens": 1}}})
	if !f.refuse {
		// 생각 블록(내용 없음)이 먼저 와도 답 조각만 흘려야 한다
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "thinking", "thinking": "", "signature": ""}})
		send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "text", "text": ""}})
		for _, p := range splitRunes(f.answer, 6) {
			send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "text_delta", "text": p}})
		}
		send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 1})
	}
	send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 9}})
	send("message_stop", map[string]any{"type": "message_stop"})
}

func newClaudeService(t *testing.T, f *fakeClaude, mod func(*Options)) *Service {
	t.Helper()
	o := Options{
		AnthropicKey: "test-key", ClaudeBaseURL: f.URL, Timeout: 5 * time.Second,
		Review: fixtureReview(), Audit: fixtureAudit(), Summary: fakeSummary{}, Scans: fixtureScans(), Policies: fakePolicies{},
	}
	if mod != nil {
		mod(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 규칙으로 고른 도구 → 답 스트리밍 1회. 요청 모양: 기본 모델 · 키 헤더 · effort low · 서버 쪽 대체(fallbacks default) · system 은 따로
func TestClaudeStreamOrderAndRequest(t *testing.T) {
	f := newFakeClaude(t)
	s := newClaudeService(t, f, nil)
	rec := ask(t, s, Request{Question: "판정 대기 요약해 줘"})
	if got, want := rec.names(), []string{"token", "facts", "links", "done"}; !slices.Equal(got, want) {
		t.Fatalf("순서 = %v, want %v", got, want)
	}
	if rec.text() != f.answer {
		t.Errorf("답 = %q, want %q (생각 블록은 흘리지 않음)", rec.text(), f.answer)
	}
	rs := f.requests()
	if len(rs) != 1 {
		t.Fatalf("요청 %d번, want 1(도구는 규칙으로 골랐다)", len(rs))
	}
	r := rs[0]
	if r.Model != DefaultClaudeModel || DefaultClaudeModel != "claude-opus-5-5" {
		t.Errorf("model = %q", r.Model)
	}
	if !r.Stream || r.key != "test-key" {
		t.Errorf("stream=%v key=%q", r.Stream, r.key)
	}
	if r.OutputConfig["effort"] != "low" {
		t.Errorf("effort = %v, want low", r.OutputConfig["effort"])
	}
	if r.Fallbacks != "default" || !strings.Contains(r.beta, "server-side-fallback-2026-07-01") {
		t.Errorf("fallbacks = %v beta = %q", r.Fallbacks, r.beta)
	}
	if r.Thinking != nil || r.Temperature != nil {
		t.Errorf("thinking · temperature 는 보내지 않는다(Opus 5.5 에서 400): %v %v", r.Thinking, r.Temperature)
	}
	if sys := r.systemText(); !strings.Contains(sys, "개조식 명사형으로 종결하세요") || !strings.Contains(sys, "격식 있는 비즈니스 어조(~입니다, ~로 확인됩니다)") {
		t.Errorf("답 형식(11/06 화면 문구 규칙)이 system 에 없음: %q", sys)
	}
	if !strings.HasPrefix(r.systemText(), "너는 SupplyGuard 보안 도우미다") {
		t.Errorf("system = %q", r.systemText())
	}
	if n := len(r.Messages); n != 1 || r.Messages[0].Role != "user" || !strings.Contains(r.Messages[0].Content[0].Text, "조회한 사실") {
		t.Errorf("messages = %+v", r.Messages)
	}
	if e := s.Engine(); e.Provider != "claude" || e.Model != "claude-opus-5-5" || e.Backup != "" {
		t.Errorf("engine = %+v", e)
	}
}

// 규칙으로 못 고르면 도구 고르기 1회(stream:false, 도구 7개) → tool_use 를 그대로 조회에 쓴다
func TestClaudeToolCallOnce(t *testing.T) {
	f := newFakeClaude(t)
	f.toolName, f.toolArgs = ToolAudit, map[string]any{"container": "web-api"}
	s := newClaudeService(t, f, nil)
	rec := ask(t, s, Request{Question: "어제 무슨 일 있었어?"})
	if got, want := rec.names(), []string{"token", "facts", "links", "done"}; !slices.Equal(got, want) {
		t.Fatalf("순서 = %v, want %v", got, want)
	}
	rs := f.requests()
	if len(rs) != 2 || rs[0].Stream || !rs[1].Stream {
		t.Fatalf("요청 = %d번(첫 번째 stream=%v)", len(rs), len(rs) > 0 && rs[0].Stream)
	}
	if len(rs[0].Tools) != len(toolDefs) {
		t.Fatalf("도구 %d개, want %d", len(rs[0].Tools), len(toolDefs))
	}
	for _, tl := range rs[0].Tools {
		if tl.InputSchema["type"] != "object" {
			t.Errorf("%s input_schema.type = %v", tl.Name, tl.InputSchema["type"])
		}
	}
	if fs := rec.get("facts").(Facts); fs.Tool != ToolAudit || !strings.Contains(joined(fs), "web-api") {
		t.Errorf("facts = %+v", fs)
	}
}

// 도구 없이 답하면 그 text 를 그대로 보이고 끝(답 스트리밍 없음)
func TestClaudeNoToolAnswersDirect(t *testing.T) {
	f := newFakeClaude(t)
	f.toolText = "SupplyGuard 는 설치 검사 · 런타임 감시를 합니다."
	s := newClaudeService(t, f, nil)
	rec := ask(t, s, Request{Question: "안녕"})
	if got, want := rec.names(), []string{"token", "facts", "links", "done"}; !slices.Equal(got, want) {
		t.Fatalf("순서 = %v, want %v", got, want)
	}
	if rec.text() != f.toolText || len(f.requests()) != 1 {
		t.Errorf("답 = %q, 요청 %d번", rec.text(), len(f.requests()))
	}
}

// 안전 장치 거절(stop_reason refusal) — 조회한 사실은 그대로 보내고 거절 안내로 끝낸다
func TestClaudeRefusalKeepsFacts(t *testing.T) {
	f := newFakeClaude(t)
	f.refuse = true
	s := newClaudeService(t, f, nil)
	rec := ask(t, s, Request{Question: "판정 대기 요약해 줘"})
	if got, want := rec.names(), []string{"facts", "links", "error"}; !slices.Equal(got, want) {
		t.Fatalf("순서 = %v, want %v", got, want)
	}
	if e, _ := rec.get("error").(string); e != MsgRefused {
		t.Errorf("error = %q, want %q", e, MsgRefused)
	}
	if fs := rec.get("facts").(Facts); !strings.Contains(joined(fs), "판정 대기 건은 2개") {
		t.Errorf("facts = %+v", fs)
	}
}

// Claude 에 닿지 못하면(5xx · 401 · 429) Ollama 예비로 같은 질문에 답한다. 예비가 없으면 연결 실패 안내
func TestClaudeDownUsesOllamaBackup(t *testing.T) {
	for _, code := range []int{529, 500, 401, 429} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newFakeClaude(t)
			f.status = code
			o := newFakeOllama(t)
			s := newClaudeService(t, f, func(op *Options) { op.OllamaURL, op.Model = o.URL, "qwen2.5:3b" })
			if e := s.Engine(); e.Provider != "claude" || e.Backup != "ollama" {
				t.Fatalf("engine = %+v", e)
			}
			rec := ask(t, s, Request{Question: "판정 대기 요약해 줘"})
			if got, want := rec.names(), []string{"token", "facts", "links", "done"}; !slices.Equal(got, want) {
				t.Fatalf("순서 = %v, want %v", got, want)
			}
			if rec.text() != o.answer || len(o.requests()) != 1 {
				t.Errorf("예비 답 = %q, ollama 요청 %d번", rec.text(), len(o.requests()))
			}
		})
	}
	t.Run("예비 없음", func(t *testing.T) {
		f := newFakeClaude(t)
		f.status = 401
		s := newClaudeService(t, f, nil)
		rec := ask(t, s, Request{Question: "판정 대기 요약해 줘"})
		if got, want := rec.names(), []string{"facts", "links", "error"}; !slices.Equal(got, want) {
			t.Fatalf("순서 = %v, want %v", got, want)
		}
		if e, _ := rec.get("error").(string); e != MsgModelDown {
			t.Errorf("error = %q", e)
		}
	})
}

// 이전 대화: 첫 턴은 user 여야 하고 같은 역할이 이어지면 하나로 합친다(마지막은 늘 이번 질문)
func TestClaudeHistoryAlternates(t *testing.T) {
	f := newFakeClaude(t)
	s := newClaudeService(t, f, nil)
	ask(t, s, Request{Question: "판정 대기 요약해 줘", History: []Turn{
		{Role: "assistant", Text: "안녕하세요"},
		{Role: "user", Text: "첫 질문"},
		{Role: "user", Text: "덧붙임"},
		{Role: "assistant", Text: "첫 답"},
	}})
	ms := f.requests()[0].Messages
	roles := []string{}
	for _, m := range ms {
		roles = append(roles, m.Role)
	}
	if want := []string{"user", "assistant", "user"}; !slices.Equal(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
	if got := ms[0].Content[0].Text; got != "첫 질문\n\n덧붙임" {
		t.Errorf("합친 user = %q", got)
	}
}

// 고르는 법: 키 → Claude(+ OLLAMA_URL 이면 예비) · 키 없음 → Ollama · CHAT_PROVIDER=ollama 면 키가 있어도 Ollama · 둘 다 없으면 오류.
// Haiku 는 서버 쪽 대체가 없어 fallbacks 를 보내지 않는다
func TestEngineSelection(t *testing.T) {
	o := newFakeOllama(t)
	for _, c := range []struct {
		name string
		opt  Options
		want Engine
	}{
		{"키만", Options{AnthropicKey: "k"}, Engine{Provider: "claude", Model: "claude-opus-5-5"}},
		{"키 + Ollama", Options{AnthropicKey: "k", OllamaURL: o.URL}, Engine{Provider: "claude", Model: "claude-opus-5-5", Backup: "ollama"}},
		{"Ollama 만", Options{OllamaURL: o.URL}, Engine{Provider: "ollama", Model: "qwen2.5:3b"}},
		{"강제 ollama", Options{Provider: "ollama", AnthropicKey: "k", OllamaURL: o.URL}, Engine{Provider: "ollama", Model: "qwen2.5:3b"}},
		{"모델 바꿈", Options{AnthropicKey: "k", ClaudeModel: "claude-sonnet-5-5"}, Engine{Provider: "claude", Model: "claude-sonnet-5-5"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := New(c.opt)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Engine(); got != c.want {
				t.Errorf("engine = %+v, want %+v", got, c.want)
			}
		})
	}
	for name, opt := range map[string]Options{
		"없음":              {},
		"claude 인데 키 없음":  {Provider: "claude", OllamaURL: o.URL},
		"ollama 인데 주소 없음": {Provider: "ollama", AnthropicKey: "k"},
		"모르는 값":           {Provider: "gpt", AnthropicKey: "k"},
	} {
		if _, err := New(opt); err == nil {
			t.Errorf("%s: 오류여야 함", name)
		}
	}

	f := newFakeClaude(t)
	s := newClaudeService(t, f, func(op *Options) { op.ClaudeModel = "claude-haiku-5-5" })
	ask(t, s, Request{Question: "판정 대기 요약해 줘"})
	if r := f.requests()[0]; r.Fallbacks != nil || strings.Contains(r.beta, "server-side-fallback") {
		t.Errorf("haiku 에 fallbacks = %v beta = %q", r.Fallbacks, r.beta)
	}
}
