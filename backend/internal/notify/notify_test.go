package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const secret = "T000/B000/xoxb-SECRET-TOKEN"

// sink: 받은 본문을 채널로 넘기는 수신 서버. status 로 응답 코드를 순서대로 지정한다(모자라면 200).
type sink struct {
	srv    *httptest.Server
	bodies chan []byte
	hits   atomic.Int32
	status []int
	gate   chan struct{} // nil 이 아니면 응답 전에 받을 때까지 기다린다
	seen   chan struct{} // 요청이 핸들러에 들어오면 신호
}

func newSink(t *testing.T, status ...int) *sink {
	t.Helper()
	s := &sink{bodies: make(chan []byte, 1024), status: status, seen: make(chan struct{}, 1024)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(s.hits.Add(1))
		b, _ := io.ReadAll(r.Body)
		s.seen <- struct{}{}
		if s.gate != nil {
			<-s.gate
		}
		code := http.StatusOK
		if n-1 < len(s.status) {
			code = s.status[n-1]
		}
		w.WriteHeader(code)
		if code == http.StatusOK {
			s.bodies <- b
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// url: 토큰이 경로에 들어간 주소 — 로그 · Status 에 새지 않는지 본다
func (s *sink) url() string { return s.srv.URL + "/services/" + secret }

func (s *sink) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case b := <-s.bodies:
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("json: %v\n%s", err, b)
		}
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("알림이 오지 않음")
		return nil
	}
}

func fast(cfg Config) Config {
	cfg.Backoff = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}
	cfg.Timeout = 2 * time.Second
	return cfg
}

// syncBuf: 채널 고루틴이 로그를 쓰는 동안 테스트가 읽어도 경쟁이 없게(-race, 11/06 새 clone 의 make test 에서 600번 중 4번 DATA RACE)
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func start(t *testing.T, cfg Config) (*Service, *syncBuf) {
	t.Helper()
	logBuf := &syncBuf{}
	s := New(fast(cfg), slog.New(slog.NewTextHandler(logBuf, nil)))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	})
	return s, logBuf
}

func killVerdict(container, rule string) model.Verdict {
	return model.Verdict{
		Event: model.Event{
			Kind: model.KindConnect, Timestamp: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC),
			ContainerID: "abcdef0123456789deadbeef", ContainerName: container, ImageName: "python:3.12-slim",
			Comm: "python", DstIP: "203.0.113.9", DstPort: 4444, DstHost: "evil.example",
		},
		Matched: true, RuleID: rule, Action: model.ActionKill, Reason: "허용되지 않은 목적지", Enforced: true,
		CaseID: ptrStr("case-7"), Install: &model.InstallRef{ID: "inst-3", Label: "pip reqeusts"},
	}
}

func ptrStr(s string) *string { return &s }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("시간 초과: %s", what)
}

// ── 페이로드 모양 ───────────────────────────────────────────

func TestWebhookPayloadViolation(t *testing.T) {
	hook := newSink(t)
	s, _ := start(t, Config{WebhookURL: hook.url(), PublicURL: "https://sg.example.com/"})
	m, ok := FromVerdict(killVerdict("sg-install-a1", "deny-hosts"))
	if !ok {
		t.Fatal("matched 판정은 메시지가 되어야 함")
	}
	s.Notify(context.Background(), m)
	got := hook.next(t)

	if got["kind"] != "violation" {
		t.Errorf("kind = %v", got["kind"])
	}
	if got["link"] != "https://sg.example.com/installs?id=inst-3" {
		t.Errorf("link = %v (PUBLIC_URL + /installs?id= 이어야 함)", got["link"])
	}
	if !strings.Contains(got["title"].(string), "격리") || !strings.Contains(got["title"].(string), "sg-install-a1") {
		t.Errorf("title = %v", got["title"])
	}
	if _, has := got["suppressed"]; has {
		t.Errorf("첫 알림에 suppressed 가 있으면 안 됨: %v", got["suppressed"])
	}
	v, _ := got["violation"].(map[string]any)
	want := map[string]any{
		"container": "sg-install-a1", "containerId": "abcdef012345", "image": "python:3.12-slim",
		"ruleId": "deny-hosts", "verdict": "kill", "reason": "허용되지 않은 목적지",
		"detail": "203.0.113.9:4444 (evil.example)", "at": "2026-10-20T09:00:00Z", "caseId": "case-7", "installId": "inst-3",
	}
	for k, w := range want {
		if v[k] != w {
			t.Errorf("violation.%s = %v, want %v", k, v[k], w)
		}
	}
	if _, has := v["enforceError"]; has {
		t.Error("성공한 격리에 enforceError 가 있으면 안 됨")
	}
}

func TestVerdictLabelsAndLinks(t *testing.T) {
	v := killVerdict("web-1", "r1")
	v.Install, v.CaseID = nil, nil
	m, _ := FromVerdict(v)
	if m.Link != "/topology?container=web-1" || m.Violation.Verdict != "kill" {
		t.Errorf("runtime kill: link=%s verdict=%s", m.Link, m.Violation.Verdict)
	}
	v.DryRun, v.Enforced = true, false
	m, _ = FromVerdict(v)
	if m.Violation.Verdict != "dry-run" || !strings.Contains(m.Title, "dry-run") {
		t.Errorf("dry-run: verdict=%s title=%s", m.Violation.Verdict, m.Title)
	}
	v.DryRun, v.Action = false, model.ActionAlert
	m, _ = FromVerdict(v)
	if m.Violation.Verdict != "alert" || !strings.Contains(m.Title, "경고") {
		t.Errorf("alert: verdict=%s title=%s", m.Violation.Verdict, m.Title)
	}
	v.Action, v.EnforceError = model.ActionKill, "docker: no such container"
	m, _ = FromVerdict(v)
	if !strings.Contains(m.Title, "격리 실패") || m.Violation.EnforceError == "" {
		t.Errorf("kill failed: title=%s", m.Title)
	}
	if _, ok := FromVerdict(model.Verdict{Matched: false}); ok {
		t.Error("정상 판정은 메시지가 되면 안 됨")
	}

	c := model.Case{ID: "case-1", Source: model.CaseInstall, InstallID: ptrStr("inst-9"), Label: "pip reqeusts", Violations: 3, RuleIDs: []string{"a", "b"}}
	if m := FromCase(c); m.Kind != KindCaseOpened || m.Link != "/installs?id=inst-9" || m.Case.Violations != 3 {
		t.Errorf("install case: %+v", m)
	}
	c = model.Case{ID: "case-2", Source: model.CaseRuntime, Container: "web 1", Label: "web 1"}
	if m := FromCase(c); m.Link != "/topology?container=web+1" {
		t.Errorf("runtime case link: %s", m.Link)
	}
	c = model.Case{ID: "case-3", Source: model.CaseScan, ScanID: ptrStr("scan-4")}
	if m := FromCase(c); m.Link != "/scans?id=scan-4" {
		t.Errorf("scan case link: %s", m.Link)
	}
	p := model.Proposal{ID: "prop-5", CaseID: "case-1", Decision: model.DecisionMalicious,
		Changes: []model.ProposalChange{{Op: "block", List: "packages", Value: "pip:reqeusts"}, {Op: "except", RuleID: "r", Field: "allowHosts", Value: "pypi.org"}}}
	m = FromProposal(p, "")
	if m.Kind != KindProposalPending || m.Link != "/policies?proposal=prop-5" || m.Proposal.Changes != 2 {
		t.Errorf("proposal: %+v", m)
	}
	if !strings.Contains(m.Proposal.Summary, "packages 차단 pip:reqeusts") || !strings.Contains(m.Proposal.Summary, "r 예외 allowHosts=pypi.org") {
		t.Errorf("summary: %s", m.Proposal.Summary)
	}
	if m := TestMessage(time.Now()); m.Kind != KindTest || !strings.Contains(m.Title, "테스트 발송") {
		t.Errorf("test message: %+v", m)
	}
}

func TestSlackPayload(t *testing.T) {
	slack := newSink(t)
	s, _ := start(t, Config{SlackURL: slack.url(), PublicURL: "http://localhost"})
	m := FromCase(model.Case{ID: "case-1", Source: model.CaseRuntime, Container: "web-1", Label: "web-1", Violations: 2, RuleIDs: []string{"deny-exec"}, OpenedAt: time.Now()})
	s.Notify(context.Background(), m)
	got := slack.next(t)

	if _, has := got["kind"]; has {
		t.Error("Slack 본문은 Message JSON 이 아니라 {text, blocks} 여야 함")
	}
	text, _ := got["text"].(string)
	if !strings.Contains(text, "건 열림") || !strings.Contains(text, "web-1") {
		t.Errorf("text = %q", text)
	}
	blocks, _ := got["blocks"].([]any)
	if len(blocks) != 3 {
		t.Fatalf("blocks 수 = %d, want 3 (header · section · context)", len(blocks))
	}
	types := []string{}
	for _, b := range blocks {
		types = append(types, b.(map[string]any)["type"].(string))
	}
	if strings.Join(types, ",") != "header,section,context" {
		t.Errorf("block types = %v", types)
	}
	ctxEl := blocks[2].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(ctxEl, "<http://localhost/topology?container=web-1|대시보드에서 보기>") {
		t.Errorf("context link = %q", ctxEl)
	}
	section := blocks[1].(map[string]any)["text"].(map[string]any)
	if section["type"] != "mrkdwn" || !strings.Contains(section["text"].(string), "위반 2건") {
		t.Errorf("section = %v", section)
	}
}

func TestBothChannelsGetEveryMessage(t *testing.T) {
	hook, slack := newSink(t), newSink(t)
	s, _ := start(t, Config{WebhookURL: hook.url(), SlackURL: slack.url()})
	s.Notify(context.Background(), TestMessage(time.Now()))
	if hook.next(t)["kind"] != "test" {
		t.Error("webhook kind")
	}
	if slack.next(t)["text"] == nil {
		t.Error("slack text")
	}
	st := s.Status()
	if len(st.Channels) != 2 || st.Channels[0].Name != "webhook" || st.Channels[1].Name != "slack" {
		t.Errorf("channels = %+v", st.Channels)
	}
}

// ── 재시도 ─────────────────────────────────────────────────

func TestRetryTwiceThenSuccess(t *testing.T) {
	hook := newSink(t, 500, 503) // 세 번째부터 200
	s, logBuf := start(t, Config{WebhookURL: hook.url()})
	s.Notify(context.Background(), TestMessage(time.Now()))
	hook.next(t)
	if n := hook.hits.Load(); n != 3 {
		t.Errorf("시도 수 = %d, want 3 (실패 2 + 성공 1)", n)
	}
	waitFor(t, "sent 집계", func() bool { return s.Status().Sent == 1 })
	st := s.Status()
	if st.Failed != 0 {
		t.Errorf("status failed=%d, want 0", st.Failed)
	}
	if st.LastError != "" {
		t.Errorf("성공으로 끝났으면 LastError 는 비어야 함: %q", st.LastError)
	}
	if !strings.Contains(logBuf.String(), "notify retry") {
		t.Error("재시도 로그가 없음")
	}
}

func TestGiveUpAfterBackoffAnd4xxNoRetry(t *testing.T) {
	hook := newSink(t, 500, 500, 500, 500, 400)
	s, _ := start(t, Config{WebhookURL: hook.url()})
	s.Notify(context.Background(), TestMessage(time.Now()))
	waitFor(t, "첫 메시지 포기", func() bool { return s.Status().Failed == 1 })
	if n := hook.hits.Load(); n != 4 {
		t.Errorf("시도 수 = %d, want 4 (최초 1 + 재시도 3)", n)
	}
	st := s.Status()
	if !strings.Contains(st.LastError, "HTTP 500") || !strings.Contains(st.LastError, "4회") {
		t.Errorf("LastError = %q", st.LastError)
	}

	s.Notify(context.Background(), TestMessage(time.Now())) // 400 → 재시도 없이 포기
	waitFor(t, "두 번째 메시지 포기", func() bool { return s.Status().Failed == 2 })
	if n := hook.hits.Load(); n != 5 {
		t.Errorf("4xx 뒤 시도 수 = %d, want 5 (재시도 없음)", n)
	}
}

// ── 큐 넘침 · 비동기 ─────────────────────────────────────────

func TestQueueOverflowDropsOldest(t *testing.T) {
	hook := newSink(t)
	hook.gate = make(chan struct{})
	s, _ := start(t, Config{WebhookURL: hook.url(), QueueSize: 4})

	first := TestMessage(time.Now())
	first.Title = "m0"
	s.Notify(context.Background(), first)
	<-hook.seen // 워커가 m0 을 꺼내 서버에서 막혀 있음 → 큐는 비어 있음
	for i := 1; i <= 7; i++ {
		m := TestMessage(time.Now())
		m.Title = "m" + string(rune('0'+i))
		s.Notify(context.Background(), m)
	}
	st := s.Status()
	if st.Dropped != 3 || st.Channels[0].Queued != 4 {
		t.Errorf("dropped=%d queued=%d, want 3/4", st.Dropped, st.Channels[0].Queued)
	}
	close(hook.gate)
	titles := []string{}
	for i := 0; i < 5; i++ {
		titles = append(titles, hook.next(t)["title"].(string))
	}
	if strings.Join(titles, ",") != "m0,m4,m5,m6,m7" {
		t.Errorf("보낸 순서 = %v (가장 오래된 m1~m3 가 버려져야 함)", titles)
	}
	waitFor(t, "sent 집계", func() bool { return s.Status().Sent == 5 })
}

func TestNotifyNeverBlocks(t *testing.T) {
	hook := newSink(t)
	hook.gate = make(chan struct{})
	defer close(hook.gate)
	s, _ := start(t, Config{WebhookURL: hook.url()})
	startAt := time.Now()
	for i := 0; i < 2000; i++ {
		s.Notify(context.Background(), TestMessage(time.Now()))
	}
	if d := time.Since(startAt); d > 200*time.Millisecond {
		t.Errorf("Notify 2000회에 %v — 호출자가 막히고 있음", d)
	}
	if st := s.Status(); st.Dropped < 1000 || st.Channels[0].Queued != 256 {
		t.Errorf("dropped=%d queued=%d (기본 큐 256)", st.Dropped, st.Channels[0].Queued)
	}
}

// ── 디바운스 ────────────────────────────────────────────────

func TestDebounceSameContainerAndRule(t *testing.T) {
	hook := newSink(t)
	s, _ := start(t, Config{WebhookURL: hook.url()})
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	send := func(container, rule string) {
		m, _ := FromVerdict(killVerdict(container, rule))
		s.Notify(context.Background(), m)
	}

	send("sg-install-a", "deny-hosts") // 보냄
	now = now.Add(10 * time.Second)
	send("sg-install-a", "deny-hosts") // 합침
	now = now.Add(20 * time.Second)
	send("sg-install-a", "deny-hosts") // 합침
	send("sg-install-a", "deny-exec")  // 다른 규칙 → 보냄
	send("sg-install-b", "deny-hosts") // 다른 컨테이너 → 보냄
	now = now.Add(31 * time.Second)    // 첫 발송에서 61초
	send("sg-install-a", "deny-hosts") // 보냄, suppressed 2

	got := []map[string]any{hook.next(t), hook.next(t), hook.next(t), hook.next(t)}
	key := func(m map[string]any) string {
		v := m["violation"].(map[string]any)
		return v["container"].(string) + "/" + v["ruleId"].(string)
	}
	if k := key(got[0]); k != "sg-install-a/deny-hosts" || got[0]["suppressed"] != nil {
		t.Errorf("1번째: %s suppressed=%v", k, got[0]["suppressed"])
	}
	if k := key(got[1]); k != "sg-install-a/deny-exec" {
		t.Errorf("2번째: %s", k)
	}
	if k := key(got[2]); k != "sg-install-b/deny-hosts" {
		t.Errorf("3번째: %s", k)
	}
	if k := key(got[3]); k != "sg-install-a/deny-hosts" || got[3]["suppressed"] != float64(2) {
		t.Errorf("4번째: %s suppressed=%v, want 2", k, got[3]["suppressed"])
	}
	select {
	case b := <-hook.bodies:
		t.Errorf("디바운스로 막혔어야 할 알림이 옴: %s", b)
	case <-time.After(50 * time.Millisecond):
	}
	waitFor(t, "sent 집계", func() bool { return s.Status().Sent == 4 })
	if st := s.Status(); st.Suppressed != 2 {
		t.Errorf("status suppressed=%d, want 2", st.Suppressed)
	}
}

func TestDebounceDoesNotApplyToOtherKinds(t *testing.T) {
	hook := newSink(t)
	s, _ := start(t, Config{WebhookURL: hook.url()})
	c := model.Case{ID: "case-1", Source: model.CaseRuntime, Container: "web-1", Label: "web-1"}
	s.Notify(context.Background(), FromCase(c))
	s.Notify(context.Background(), FromCase(c))
	hook.next(t)
	hook.next(t)
}

// ── 비활성 · Status · 비밀 보호 ─────────────────────────────

func TestDisabledIsNoop(t *testing.T) {
	s, logBuf := start(t, Config{})
	if s.Enabled() {
		t.Error("URL 이 둘 다 비면 비활성이어야 함")
	}
	s.Notify(context.Background(), TestMessage(time.Now())) // 패닉 · 블로킹 없이 무시
	st := s.Status()
	if st.Enabled || len(st.Channels) != 0 || st.Sent != 0 {
		t.Errorf("status = %+v", st)
	}
	if b, _ := json.Marshal(st); !strings.Contains(string(b), `"channels":[]`) {
		t.Errorf("channels 는 null 이 아니라 [] 여야 함: %s", b)
	}
	if strings.Contains(logBuf.String(), "notify enabled") {
		t.Error("비활성인데 enabled 로그가 찍힘")
	}
	var n Notifier = Nop{}
	n.Notify(context.Background(), TestMessage(time.Now()))
	if (Nop{}).Status().Enabled {
		t.Error("Nop 은 비활성")
	}
}

func TestStatusAndSecretsNotLeaked(t *testing.T) {
	hook := newSink(t, 500)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // 연결 거부 → *url.Error (문자열에 전체 URL 이 들어간다)
	s, logBuf := start(t, Config{WebhookURL: hook.url(), SlackURL: dead.URL + "/services/" + secret})

	s.Notify(context.Background(), TestMessage(time.Now()))
	hook.next(t)
	waitFor(t, "slack 포기 · webhook 성공", func() bool { st := s.Status(); return st.Failed == 1 && st.Sent == 1 })

	st := s.Status()
	if !st.Enabled || st.Sent != 1 || st.Failed != 1 || st.Dropped != 0 {
		t.Errorf("status = %+v", st)
	}
	if st.Channels[0].Host != strings.TrimPrefix(hook.srv.URL, "http://") || st.Channels[1].Host == "" {
		t.Errorf("host = %q / %q", st.Channels[0].Host, st.Channels[1].Host)
	}
	if st.Channels[0].LastAt == nil || st.Channels[0].Queued != 0 {
		t.Errorf("webhook channel = %+v", st.Channels[0])
	}
	if !strings.HasPrefix(st.LastError, "slack: ") || !strings.Contains(st.LastError, "4회") {
		t.Errorf("LastError = %q", st.LastError)
	}
	js, _ := json.Marshal(st)
	for name, text := range map[string]string{"Status JSON": string(js), "로그": logBuf.String()} {
		if strings.Contains(text, secret) || strings.Contains(text, "/services/") {
			t.Errorf("%s 에 URL 경로 · 토큰이 들어 있음:\n%s", name, text)
		}
	}
	if !strings.Contains(logBuf.String(), "notify enabled") || !strings.Contains(logBuf.String(), "notify failed") {
		t.Errorf("로그 내용:\n%s", logBuf.String())
	}
}

func TestCloseDrainsQueue(t *testing.T) {
	hook := newSink(t)
	s := New(fast(Config{WebhookURL: hook.url()}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 5; i++ {
		s.Notify(context.Background(), TestMessage(time.Now()))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.Close(ctx)
	if st := s.Status(); st.Sent != 5 {
		t.Errorf("Close 뒤 sent=%d, want 5 (남은 큐를 보내고 끝나야 함)", st.Sent)
	}
	s.Notify(context.Background(), TestMessage(time.Now())) // 닫힌 뒤 호출은 무시
	if st := s.Status(); st.Channels[0].Queued != 0 {
		t.Error("닫힌 뒤 큐에 들어가면 안 됨")
	}
}
