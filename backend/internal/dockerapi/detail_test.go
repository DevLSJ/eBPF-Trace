package dockerapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 감시 중 컨테이너 상세(11/10): Docker inspect 에서 상태 · 시작 시각 · 재시작 횟수 · 포트 · 라벨만 읽는다.
// 환경 변수(Config.Env)는 비밀이 담길 수 있어 읽지도 내보내지도 않는다. 없는 컨테이너는 ErrNotFound
const inspectWithSecret = `{"Id":"abc123","Name":"/shop-api","Image":"sha256:feed","RestartCount":2,
 "State":{"Status":"running","Running":true,"Pid":42,"StartedAt":"2026-11-10T01:02:03.456Z"},
 "Config":{"Image":"node:22","Env":["DB_PASSWORD=hunter2-secret","PATH=/usr/bin"],"Labels":{"supplyguard.watch":"true"}},
 "NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}],"443/tcp":null}}}`

func TestInspectDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/abc123/json":
			_, _ = w.Write([]byte(inspectWithSecret))
		case "/containers/fresh/json":
			_, _ = w.Write([]byte(`{"Id":"fresh","Name":"/x","Config":{"Image":"busybox"},"State":{"Status":"created","StartedAt":"0001-01-01T00:00:00Z"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container"}`))
		}
	}))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, err := c.InspectDetail(ctx, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 10, 1, 2, 3, 456_000_000, time.UTC)
	if d.ID != "abc123" || d.Name != "shop-api" || d.Image != "node:22" || d.ImageID != "sha256:feed" || d.State != "running" ||
		d.RestartCount != 2 || d.StartedAt == nil || !d.StartedAt.Equal(want) || d.Labels["supplyguard.watch"] != "true" {
		t.Fatalf("detail = %+v", d)
	}
	if len(d.Ports) != 2 || d.Ports[0].Port != "443/tcp" || d.Ports[0].HostPort != "" || d.Ports[1].Port != "8080/tcp" || d.Ports[1].HostPort != "18080" || d.Ports[1].HostIP != "0.0.0.0" {
		t.Fatalf("ports = %+v", d.Ports)
	}
	b, _ := json.Marshal(d)
	if s := string(b); strings.Contains(s, "hunter2") || strings.Contains(s, "DB_PASSWORD") || strings.Contains(strings.ToLower(s), `"env"`) {
		t.Fatalf("환경 변수가 나갔다: %s", s)
	}
	// 시작한 적 없는 컨테이너: 시작 시각 없음 · 빈 포트 · 빈 라벨(null 아님)
	f, err := c.InspectDetail(ctx, "fresh")
	if err != nil || f.StartedAt != nil || f.State != "created" || f.Ports == nil || f.Labels == nil {
		t.Fatalf("fresh = %+v %v", f, err)
	}
	if _, err := c.InspectDetail(ctx, "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	// 예전 오류 문장은 그대로(로그 · 다른 호출자)
	if _, err := c.Inspect(ctx, "gone"); err == nil || !strings.Contains(err.Error(), "404") || !errors.Is(err, ErrNotFound) {
		t.Fatalf("Inspect missing = %v", err)
	}
}
