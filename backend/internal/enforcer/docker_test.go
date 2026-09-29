package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDockerKill(t *testing.T) {
	var gotPath, gotSignal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotSignal = r.URL.Path, r.URL.Query().Get("signal")
		switch {
		case strings.Contains(r.URL.Path, "aaaaaaaaaaaa"):
			w.WriteHeader(http.StatusConflict)
		case r.Method != http.MethodPost:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Kill(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/containers/"+id+"/kill" || gotSignal != "SIGKILL" {
		t.Fatalf("path=%s signal=%s", gotPath, gotSignal)
	}
	if err := d.Kill(context.Background(), "aaaaaaaaaaaa"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
	if err := d.Kill(context.Background(), "../images/x"); err == nil {
		t.Fatal("invalid id must be rejected before any request")
	}
}
