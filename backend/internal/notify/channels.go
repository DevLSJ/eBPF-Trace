package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// encoder: Message → 요청 본문 (채널 형식)
type encoder func(Message) ([]byte, error)

// channel: 목적지 하나. 큐(슬라이스, 가득 차면 가장 오래된 것부터 버림) + 워커 하나.
type channel struct {
	name   string
	url    string
	host   string
	encode encoder
	cfg    Config
	log    *slog.Logger

	mu     sync.Mutex
	queue  []Message
	closed bool
	wake   chan struct{}

	sent, failed, dropped int64
	lastErr               string
	lastErrAt             time.Time
	lastAt                time.Time
}

func newChannel(name, url string, enc encoder, cfg Config, log *slog.Logger) *channel {
	return &channel{
		name: name, url: url, host: hostOf(url), encode: enc, cfg: cfg,
		log:  log.With("channel", name, "host", hostOf(url)),
		wake: make(chan struct{}, 1),
	}
}

// enqueue: 큐 끝에 넣는다. 가득 차면 맨 앞(가장 오래된 것)을 버리고 dropped 를 센다.
func (c *channel) enqueue(m Message) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if len(c.queue) >= c.cfg.QueueSize {
		c.queue = c.queue[1:]
		c.dropped++
		if c.dropped == 1 || c.dropped%100 == 0 {
			c.log.Warn("notify queue full; dropping oldest", "dropped", c.dropped)
		}
	}
	c.queue = append(c.queue, m)
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *channel) closeInput() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// pop: 다음 메시지. 비어 있으면 ok=false, 닫혔고 비었으면 done=true
func (c *channel) pop() (m Message, ok, done bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return Message{}, false, c.closed
	}
	m = c.queue[0]
	c.queue[0] = Message{}
	c.queue = c.queue[1:]
	return m, true, false
}

func (c *channel) run(ctx context.Context) {
	for {
		m, ok, done := c.pop()
		if done {
			return
		}
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-c.wake:
			}
			continue
		}
		if err := c.deliver(ctx, m); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.mu.Lock()
			c.failed++
			c.lastErr, c.lastErrAt = err.Error(), time.Now()
			c.mu.Unlock()
			c.log.Error("notify failed", "kind", m.Kind, "err", err)
			continue
		}
		c.mu.Lock()
		c.sent++
		c.lastAt = time.Now()
		c.mu.Unlock()
	}
}

// deliver: 한 번 보내고, 실패하면 Backoff 간격으로 다시 시도한다.
func (c *channel) deliver(ctx context.Context, m Message) error {
	body, err := c.encode(m)
	if err != nil {
		return fmt.Errorf("encode: %w", err) // 인코딩 실패는 재시도해도 같다
	}
	var last error
	for attempt := 0; ; attempt++ {
		last = c.post(ctx, body)
		if last == nil {
			return nil
		}
		if attempt >= len(c.cfg.Backoff) || !retryable(last) {
			return fmt.Errorf("%d회 시도 후 포기: %w", attempt+1, last)
		}
		c.log.Warn("notify retry", "kind", m.Kind, "attempt", attempt+1, "wait", c.cfg.Backoff[attempt], "err", last)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.cfg.Backoff[attempt]):
		}
	}
}

// httpError: 2xx 가 아닌 응답
type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

// retryable: 네트워크 오류 · 429 · 5xx 만 다시 시도한다. 그 밖의 4xx 는 본문 · 주소 문제라 반복해도 같다.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status == http.StatusTooManyRequests || he.status >= 500
	}
	return true
}

func (c *channel) post(ctx context.Context, body []byte) error {
	rctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SupplyGuard-notify/1")
	res, err := c.cfg.Client.Do(req)
	if err != nil {
		// *url.Error 는 문자열에 전체 URL(Slack 토큰 경로 포함)을 넣는다 — 호스트와 원인만 남긴다
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("%s %s: %w", ue.Op, c.host, ue.Err)
		}
		return err
	}
	defer res.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(res.Body, 200))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &httpError{status: res.StatusCode, body: string(bytes.TrimSpace(snippet))}
	}
	return nil
}

// ── 본문 형식 ───────────────────────────────────────────────

// encodeWebhook: Message 를 그대로 JSON
func encodeWebhook(m Message) ([]byte, error) { return json.Marshal(m) }

// slackPayload: incoming webhook 최소 형식 — text(알림 미리보기 · 폴백) + blocks(제목 · 본문 · 링크)
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackText struct {
	Type  string `json:"type"` // plain_text | mrkdwn
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

func encodeSlack(m Message) ([]byte, error) {
	body := m.Text
	if m.Suppressed > 0 {
		body += fmt.Sprintf("\n(같은 컨테이너 · 규칙 알림 %d건 묶음)", m.Suppressed)
	}
	if body == "" {
		body = string(m.Kind)
	}
	blocks := []slackBlock{
		{Type: "header", Text: &slackText{Type: "plain_text", Text: truncate(m.Title, 150), Emoji: false}},
		{Type: "section", Text: &slackText{Type: "mrkdwn", Text: truncate(body, 2900)}},
	}
	ctxLine := m.At.Format(time.RFC3339)
	if m.Link != "" {
		ctxLine += " · <" + m.Link + "|대시보드에서 보기>"
	}
	blocks = append(blocks, slackBlock{Type: "context", Elements: []slackText{{Type: "mrkdwn", Text: ctxLine}}})
	return json.Marshal(slackPayload{Text: m.Title, Blocks: blocks})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	for len(string(r)) > n-1 {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// status: 집계 사본과 마지막 오류 시각(합계의 「마지막 오류」를 고를 때 쓴다)
func (c *channel) status() (ChannelStatus, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := ChannelStatus{
		Name: c.name, Host: c.host, Sent: c.sent, Failed: c.failed, Dropped: c.dropped,
		LastError: c.lastErr, Queued: len(c.queue),
	}
	if !c.lastAt.IsZero() {
		t := c.lastAt
		st.LastAt = &t
	}
	return st, c.lastErrAt
}
