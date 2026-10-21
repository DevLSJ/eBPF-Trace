package dockerapi

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func frame(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestEvidenceCalls(t *testing.T) {
	var gotLogsQuery string
	tty := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/slow/changes"):
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		case strings.HasSuffix(r.URL.Path, "/logs"):
			gotLogsQuery = r.URL.RawQuery
			if tty {
				_, _ = w.Write([]byte("raw out\nraw err\n"))
				return
			}
			_, _ = w.Write(frame(1, "out1\n"))
			_, _ = w.Write(frame(2, "err1\n"))
			_, _ = w.Write(frame(1, "out2\n"))
		case strings.HasSuffix(r.URL.Path, "/changes"):
			_, _ = w.Write([]byte(`[{"Path":"/etc/passwd","Kind":0},{"Path":"/tmp/x","Kind":1},{"Path":"/var/log/old","Kind":2}]`))
		case strings.HasSuffix(r.URL.Path, "/top"):
			_, _ = w.Write([]byte(`{"Titles":["UID","PID","PPID","C","STIME","TTY","TIME","CMD"],"Processes":[["root","1","0","0","09:00","?","00:00:00","pip install ./reqeusts"],["nobody","42","1","0","09:01","?","00:00:00","sh -c curl x"]]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	b, err := c.Logs(ctx, "abc", 200, 1<<20)
	if err != nil || string(b) != "out1\nerr1\nout2\n" {
		t.Fatalf("logs: %q %v", b, err)
	}
	if !strings.Contains(gotLogsQuery, "stdout=1") || !strings.Contains(gotLogsQuery, "stderr=1") || !strings.Contains(gotLogsQuery, "tail=200") {
		t.Fatalf("query %q", gotLogsQuery)
	}
	tty = true
	if b, err := c.Logs(ctx, "abc", 200, 1<<20); err != nil || string(b) != "raw out\nraw err\n" {
		t.Fatalf("tty logs: %q %v", b, err)
	}
	// limit 은 읽는 바이트 상한
	if b, _ := c.Logs(ctx, "abc", 200, 4); string(b) != "raw " {
		t.Fatalf("limit: %q", b)
	}

	ch, err := c.Diff(ctx, "abc")
	if err != nil || len(ch) != 3 || ch[0] != (Change{"C", "/etc/passwd"}) || ch[1] != (Change{"A", "/tmp/x"}) || ch[2] != (Change{"D", "/var/log/old"}) {
		t.Fatalf("diff: %+v %v", ch, err)
	}

	ps, err := c.Top(ctx, "abc")
	if err != nil || len(ps) != 2 || ps[0] != (Proc{1, "root", "pip install ./reqeusts"}) || ps[1] != (Proc{42, "nobody", "sh -c curl x"}) {
		t.Fatalf("top: %+v %v", ps, err)
	}

	// ctx 로 취소된다
	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Diff(cctx, "slow"); err == nil || time.Since(start) > time.Second {
		t.Fatalf("slow diff must stop with ctx: err=%v took=%v", err, time.Since(start))
	}
}

func TestIsMultiplexed(t *testing.T) {
	if isMultiplexed([]byte("hello world\n")) || isMultiplexed(nil) {
		t.Fatal("text must not look multiplexed")
	}
	if !isMultiplexed(frame(1, "x")) || !isMultiplexed(frame(0, "")) {
		t.Fatal("frames must be detected")
	}
}
