package notify

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config: 환경 변수에서 온 값. WebhookURL · SlackURL 둘 다 비면 비활성(Enabled 가 false, Notify 는 no-op).
type Config struct {
	WebhookURL string // NOTIFY_WEBHOOK_URL — Message 를 JSON 으로 POST
	SlackURL   string // NOTIFY_SLACK_URL — Slack incoming webhook ({"text", "blocks"})
	PublicURL  string // PUBLIC_URL — 대시보드 링크 앞에 붙이는 주소 (예: https://sg.example.com). 비면 경로만 보낸다

	// 아래는 비워 두면 기본값. 테스트에서만 바꾼다.
	Timeout   time.Duration   // 요청 하나의 제한 (기본 5s)
	Backoff   []time.Duration // 재시도 간격 (기본 1s · 4s · 16s = 3회)
	QueueSize int             // 채널별 큐 (기본 256)
	Debounce  time.Duration   // 같은 컨테이너 · 규칙 위반을 묶는 창 (기본 60s)
	Client    *http.Client    // nil 이면 Timeout 으로 만든다
}

const (
	defaultTimeout   = 5 * time.Second
	defaultQueueSize = 256
	defaultDebounce  = 60 * time.Second
)

var defaultBackoff = []time.Duration{time.Second, 4 * time.Second, 16 * time.Second}

// Enabled: 채널이 하나라도 설정되어 있는가
func (c Config) Enabled() bool { return c.WebhookURL != "" || c.SlackURL != "" }

// Service: Notifier 구현. 채널마다 큐 + 워커 하나.
type Service struct {
	cfg      Config
	log      *slog.Logger
	channels []*channel
	now      func() time.Time

	mu         sync.Mutex
	debounce   map[string]*debounceEntry // 컨테이너+규칙 → 마지막 발송 · 합쳐진 수
	suppressed int64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type debounceEntry struct {
	lastSent time.Time
	pending  int
}

// New: 설정으로 서비스를 만들고 워커를 띄운다. 비활성이면 워커 없이 no-op 으로 동작한다(Nop 을 따로 고르지 않아도 된다).
// 끝낼 때 Close 를 부른다.
func New(cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Backoff == nil {
		cfg.Backoff = defaultBackoff
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = defaultDebounce
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: cfg.Timeout}
	}
	s := &Service{cfg: cfg, log: log, now: time.Now, debounce: map[string]*debounceEntry{}}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	if cfg.WebhookURL != "" {
		s.channels = append(s.channels, newChannel("webhook", cfg.WebhookURL, encodeWebhook, cfg, log))
	}
	if cfg.SlackURL != "" {
		s.channels = append(s.channels, newChannel("slack", cfg.SlackURL, encodeSlack, cfg, log))
	}
	for _, ch := range s.channels {
		s.wg.Add(1)
		go func(ch *channel) {
			defer s.wg.Done()
			ch.run(ctx)
		}(ch)
	}
	if len(s.channels) > 0 {
		hosts := make([]string, 0, len(s.channels))
		for _, ch := range s.channels {
			hosts = append(hosts, ch.name+"="+ch.host)
		}
		log.Info("notify enabled", "channels", strings.Join(hosts, ","), "timeout", cfg.Timeout, "queue", cfg.QueueSize)
	}
	return s
}

// Enabled: 보낼 채널이 있는가
func (s *Service) Enabled() bool { return len(s.channels) > 0 }

// Notify: 큐에 넣고 바로 돌아온다. ctx 는 이미 끝났을 때만 본다(그 호출은 버린다).
// violation 은 컨테이너 · 규칙별로 디바운스한다. 나머지 종류는 항상 보낸다.
func (s *Service) Notify(ctx context.Context, m Message) {
	if !s.Enabled() {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}
	if m.At.IsZero() {
		m.At = s.now()
	}
	if m.Kind == KindViolation {
		if !s.passDebounce(&m) {
			return
		}
	}
	m.Link = s.absoluteLink(m.Link)
	for _, ch := range s.channels {
		ch.enqueue(m)
	}
}

// passDebounce: 같은 키의 알림을 창 안에서 한 번만 통과시킨다. 통과하는 메시지에 그동안 합쳐진 수를 Suppressed 로 넣는다.
func (s *Service) passDebounce(m *Message) bool {
	key := debounceKey(*m)
	if key == "" {
		return true
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.debounce[key]
	if ok && now.Sub(e.lastSent) < s.cfg.Debounce {
		e.pending++
		s.suppressed++
		return false
	}
	if !ok {
		e = &debounceEntry{}
		s.debounce[key] = e
	}
	m.Suppressed = e.pending
	e.pending = 0
	e.lastSent = now
	// 오래된 키 정리 (창의 두 배 이상 지난 것)
	if len(s.debounce) > 1024 {
		for k, x := range s.debounce {
			if now.Sub(x.lastSent) > 2*s.cfg.Debounce {
				delete(s.debounce, k)
			}
		}
	}
	return true
}

func debounceKey(m Message) string {
	if m.Violation == nil {
		return ""
	}
	return m.Violation.Container + "\x00" + m.Violation.RuleID
}

func (s *Service) absoluteLink(link string) string {
	if link == "" || s.cfg.PublicURL == "" || !strings.HasPrefix(link, "/") {
		return link
	}
	return strings.TrimRight(s.cfg.PublicURL, "/") + link
}

// Status: 채널별 · 합계 집계
func (s *Service) Status() Status {
	st := Status{Enabled: s.Enabled(), Channels: []ChannelStatus{}}
	var lastAt time.Time
	for _, ch := range s.channels {
		c, errAt := ch.status()
		st.Channels = append(st.Channels, c)
		st.Sent += c.Sent
		st.Failed += c.Failed
		st.Dropped += c.Dropped
		if c.LastError != "" && (st.LastError == "" || errAt.After(lastAt)) {
			st.LastError, lastAt = c.Name+": "+c.LastError, errAt
		}
	}
	s.mu.Lock()
	st.Suppressed = s.suppressed
	s.mu.Unlock()
	return st
}

// Close: 워커를 멈춘다. 큐에 남은 것은 ctx 가 끝날 때까지 보내 보고, 그 뒤는 버린다.
func (s *Service) Close(ctx context.Context) {
	for _, ch := range s.channels {
		ch.closeInput()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.cancel()
		<-done
	}
	s.cancel()
}
