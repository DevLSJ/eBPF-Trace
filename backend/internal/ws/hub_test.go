package ws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBroadcastAndOrigin(t *testing.T) {
	hub := NewHub([]string{"http://localhost:5173"})
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	// 허용되지 않은 Origin은 거부
	h := http.Header{"Origin": []string{"http://evil.example"}}
	if _, _, err := websocket.DefaultDialer.Dial(url, h); err == nil {
		t.Fatal("foreign origin must be rejected")
	}

	h = http.Header{"Origin": []string{"http://localhost:5173"}}
	c, _, err := websocket.DefaultDialer.Dial(url, h)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for hub.Clients() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	hub.Broadcast("stats", map[string]int{"riskScore": 42})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, b, err := c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Type string         `json:"type"`
		Data map[string]int `json:"data"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Type != "stats" || m.Data["riskScore"] != 42 {
		t.Fatalf("unexpected frame %s (%v)", b, err)
	}
}
