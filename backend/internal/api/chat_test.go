package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/chat"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
)

// 가짜 Ollama: 스트리밍 NDJSON. release 가 있으면 첫 조각 뒤 닫힐 때까지 멈춘다
func chatOllama(t *testing.T, release chan struct{}) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		for i, p := range []string{"판정 대기 건이 ", "하나 있습니다."} {
			if i == 1 && release != nil {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			_ = enc.Encode(map[string]any{"message": map[string]string{"role": "assistant", "content": p}, "done": false})
			w.(http.Flusher).Flush()
		}
		_ = enc.Encode(map[string]any{"message": map[string]string{"role": "assistant", "content": ""}, "done": true})
	}))
	t.Cleanup(srv.Close)
	return srv
}

type chatCases struct{}

func (chatCases) Cases() []model.Case {
	id := "inst-0001"
	return []model.Case{{ID: "case-0001", Source: model.CaseInstall, InstallID: &id, Container: "sg-install-a", Label: "pip ./reqeusts",
		Level: model.LevelKilled, Violations: 2, RuleIDs: []string{"no-shell-download"}, State: model.CaseOpen, Decision: model.DecisionPending}}
}
func (chatCases) Blocklist() model.Blocklist { return model.Blocklist{} }

func chatServer(t *testing.T, ollamaURL string) *httptest.Server {
	svc, err := chat.New(chat.Options{OllamaURL: ollamaURL, Model: "qwen2.5:3b", KeepAlive: "30m", Timeout: 5 * time.Second, Review: chatCases{}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ChatHandler(svc))
	t.Cleanup(srv.Close)
	return srv
}

type sse struct{ event, data string }

func readSSE(t *testing.T, resp *http.Response) (evs []sse, comments int) {
	t.Helper()
	sc := bufio.NewScanner(resp.Body)
	var cur sse
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.event != "" {
				evs = append(evs, cur)
			}
			cur = sse{}
		case strings.HasPrefix(line, ": ping"):
			comments++
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		}
	}
	return evs, comments
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestChatHandlerSSE(t *testing.T) {
	srv := chatServer(t, chatOllama(t, nil).URL)
	resp := post(t, srv.URL, `{"question":"판정 대기 요약해 줘","page":"/","history":[]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("버퍼링 · 캐시 헤더 = %v", resp.Header)
	}
	evs, _ := readSSE(t, resp)
	names, text := []string{}, ""
	for _, e := range evs {
		if e.event == "token" {
			var s string
			if err := json.Unmarshal([]byte(e.data), &s); err != nil {
				t.Fatalf("token data 는 JSON 문자열: %q", e.data)
			}
			text += s
			if len(names) > 0 && names[len(names)-1] == "token" {
				continue
			}
		}
		names = append(names, e.event)
	}
	if want := []string{"token", "facts", "links", "done"}; !slices.Equal(names, want) {
		t.Fatalf("순서 = %v", names)
	}
	if text != "판정 대기 건이 하나 있습니다." {
		t.Errorf("text = %q", text)
	}
	var facts chat.Facts
	var links []chat.Link
	for _, e := range evs {
		switch e.event {
		case "facts":
			_ = json.Unmarshal([]byte(e.data), &facts)
		case "links":
			_ = json.Unmarshal([]byte(e.data), &links)
		}
	}
	if len(facts.Cases) != 1 || facts.Cases[0].DecisionText != "판정 대기" {
		t.Errorf("facts = %+v", facts)
	}
	if len(links) == 0 || links[0].Href != "/installs?id=inst-0001" {
		t.Errorf("links = %+v", links)
	}
}

func TestChatHandlerBadRequest(t *testing.T) {
	srv := chatServer(t, chatOllama(t, nil).URL)
	for name, body := range map[string]string{
		"501자":    `{"question":"` + strings.Repeat("가", 501) + `"}`,
		"빈 질문":    `{"question":"   "}`,
		"JSON 아님": `질문`,
	} {
		resp := post(t, srv.URL, body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
}

func TestChatHandlerBusy429(t *testing.T) {
	release := make(chan struct{})
	srv := chatServer(t, chatOllama(t, release).URL)
	var wg sync.WaitGroup
	wg.Add(1)
	started := make(chan struct{})
	go func() {
		defer wg.Done()
		resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"question":"판정 대기 요약해 줘"}`))
		if err != nil {
			t.Error(err)
			close(started)
			return
		}
		defer resp.Body.Close()
		br := bufio.NewReader(resp.Body)
		_, _ = br.ReadString('\n') // 첫 조각이 왔다 = 생성 중
		close(started)
		for {
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	<-started
	resp := post(t, srv.URL, `{"question":"판정 대기 요약해 줘"}`)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "다른 질문에 답하는 중입니다. 잠시 뒤 다시 물어 주세요" {
		t.Errorf("429 본문 = %v", body)
	}
	close(release)
	wg.Wait()
}

func TestChatHandlerKeepalive(t *testing.T) {
	old := chatPing
	chatPing = 30 * time.Millisecond
	defer func() { chatPing = old }()
	release := make(chan struct{})
	srv := chatServer(t, chatOllama(t, release).URL)
	go func() { time.Sleep(200 * time.Millisecond); close(release) }()
	resp := post(t, srv.URL, `{"question":"판정 대기 요약해 줘"}`)
	evs, comments := readSSE(t, resp)
	if comments == 0 {
		t.Errorf("모델을 기다리는 동안 keepalive 주석이 없음(nginx proxy_read_timeout)")
	}
	if len(evs) == 0 || evs[len(evs)-1].event != "done" {
		t.Errorf("끝 이벤트 = %+v", evs)
	}
}

// /api/info 의 chatEngine(11/09): 쓰는 모델 · 예비 — 설정 화면이 「밖으로 나가는 데이터」를 정한다. 키는 담지 않는다. 챗봇이 꺼져 있으면 생략
func TestInfoChatEngine(t *testing.T) {
	mem := store.NewMemory()
	svc, err := chat.New(chat.Options{AnthropicKey: "sk-ant-test-secret", OllamaURL: "http://127.0.0.1:9", Review: chatCases{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		chat     *chat.Service
		want     string
		dontWant string
	}{
		{svc, `"chatEngine":{"provider":"claude","model":"claude-opus-5-5","backup":"ollama"}`, "sk-ant-test-secret"},
		{nil, `"chat":false`, `"chatEngine"`},
	} {
		srv := httptest.NewServer(Router(Deps{Engine: rules.New(nil), Policies: mem, Audit: mem, Buffer: mem, Stats: stats.New().Snapshot, Chat: c.chat}))
		body := readBody(t, do(t, "GET", srv.URL+"/api/info", "", ""))
		srv.Close()
		if !strings.Contains(body, c.want) || strings.Contains(body, c.dontWant) {
			t.Errorf("info = %s\nwant %s, not %s", body, c.want, c.dontWant)
		}
	}
}
