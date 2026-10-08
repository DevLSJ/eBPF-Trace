package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Uplink — gateway로의 WebSocket 업링크 (docs/13 §5). GATEWAY_WS_URL 미설정 시 비활성(stdout만).
// 재접속 백오프, 접속 시 agent.hello 재전송, 15초 heartbeat. 이벤트는 best-effort(미접속 시 드롭).
type Uplink struct {
	url   string
	token string
	uid   string
	wl    *Whitelist

	mu    sync.Mutex
	conn  *websocket.Conn
	hello map[string]any
}

func newUplink(wl *Whitelist) *Uplink {
	host, _ := os.Hostname()
	return &Uplink{
		url:   os.Getenv("GATEWAY_WS_URL"),
		token: os.Getenv("AGENT_TOKEN"),
		uid:   "agent-" + host,
		wl:    wl,
	}
}

func (u *Uplink) enabled() bool { return u.url != "" }

func (u *Uplink) setHello(h map[string]any) {
	h["agentUid"] = u.uid
	u.mu.Lock()
	u.hello = h
	u.mu.Unlock()
}

func (u *Uplink) send(v map[string]any) {
	u.mu.Lock()
	c := u.conn
	u.mu.Unlock()
	if c == nil {
		return
	}
	b, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.Write(ctx, websocket.MessageText, b)
}

func (u *Uplink) event(e map[string]any) {
	if !u.enabled() {
		return
	}
	e["agentUid"] = u.uid
	u.send(e)
}

// run — 접속·재접속 루프. 접속마다 hello 전송 + heartbeat + 다운링크 수신.
func (u *Uplink) run(ctx context.Context) {
	if !u.enabled() {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if err := u.connectOnce(ctx); err != nil {
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (u *Uplink) connectOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dialCtx, u.url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + u.token}},
	})
	if err != nil {
		log.Printf("uplink: dial %s failed: %v", u.url, err)
		return err
	}
	log.Printf("uplink: connected to %s", u.url)
	c.SetReadLimit(1 << 20)
	u.mu.Lock()
	u.conn = c
	hello := u.hello
	u.mu.Unlock()

	if hello != nil {
		b, _ := json.Marshal(hello)
		wctx, wcancel := context.WithTimeout(ctx, 3*time.Second)
		_ = c.Write(wctx, websocket.MessageText, b)
		wcancel()
	}

	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go u.heartbeat(hbCtx)

	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			u.mu.Lock()
			u.conn = nil
			u.mu.Unlock()
			return err
		}
		u.handleDownlink(data)
	}
}

func (u *Uplink) heartbeat(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.send(map[string]any{"type": "agent.heartbeat", "agentUid": u.uid})
		}
	}
}

// handleDownlink — gateway 명령 처리. R-6: cmd.whitelist_update 적용. kill/block은 R-10.
func (u *Uplink) handleDownlink(data []byte) {
	var m struct {
		Type      string     `json:"type"`
		Whitelist *Whitelist `json:"whitelist"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	switch m.Type {
	case "cmd.whitelist_update":
		if m.Whitelist != nil {
			_ = u.wl.replaceFrom(m.Whitelist)
		}
	}
}
