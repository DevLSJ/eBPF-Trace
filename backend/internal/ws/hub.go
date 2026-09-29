// Package ws fans verdicts and stats out to dashboard WebSocket clients.
package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Message: WebSocket 한 프레임. type = "verdict" | "stats"
type Message struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

const (
	sendQueue  = 256
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 30 * time.Second
)

type client struct {
	conn *websocket.Conn
	send chan []byte
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
	up      websocket.Upgrader
	dropped atomic.Uint64
}

// NewHub: allowedOrigins 외에 같은 호스트(nginx 경유 동일 출처)도 허용한다.
func NewHub(allowedOrigins []string) *Hub {
	h := &Hub{clients: map[*client]struct{}{}}
	h.up = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // 브라우저가 아닌 클라이언트 (curl, websocat)
			}
			if slices.Contains(allowedOrigins, origin) {
				return true
			}
			u, err := url.Parse(origin)
			return err == nil && u.Host == r.Host
		},
	}
	return h
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.up.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade가 이미 HTTP 오류 응답을 씀
	}
	c := &client{conn: conn, send: make(chan []byte, sendQueue)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	go h.writePump(c)
	go h.readPump(c)
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
	h.mu.Unlock()
}

// readPump: 클라이언트 메시지는 쓰지 않지만, 끊김·pong을 감지하려고 읽는다.
func (h *Hub) readPump(c *client) {
	defer func() {
		h.remove(c)
		c.conn.Close()
	}()
	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *Hub) writePump(c *client) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case b, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Broadcast: 느린 클라이언트 때문에 파이프라인이 막히지 않도록 큐가 차면 버린다.
func (h *Hub) Broadcast(msgType string, data any) {
	b, err := json.Marshal(Message{Type: msgType, Data: data})
	if err != nil {
		slog.Error("ws marshal", "err", err)
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- b:
		default:
			h.dropped.Add(1)
		}
	}
}

func (h *Hub) Clients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Close: 서버 종료 시 모든 연결을 닫는다.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		delete(h.clients, c)
		close(c.send)
	}
}
