package dockerapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Tier 1 — 라벨로 연동(11/06): 감시 · 격리 범위를 정하는 컨테이너 라벨을 Docker 에서 읽는다(Inspect · List · Labels)
func TestContainerLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/abc/json":
			_, _ = w.Write([]byte(`{"Id":"abc","Name":"/shop-api","Config":{"Image":"node:22","Labels":{"supplyguard.watch":"true","com.docker.compose.service":"api"}},"State":{"Pid":42,"Running":true}}`))
		case "/containers/nolabel/json":
			_, _ = w.Write([]byte(`{"Id":"nolabel","Name":"/x","Config":{"Image":"busybox","Labels":null},"State":{"Running":true}}`))
		case "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc","Names":["/shop-api"],"Image":"node:22","State":"running","Labels":{"supplyguard.watch":"true"}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := c.Inspect(ctx, "abc")
	if err != nil || got.Labels["supplyguard.watch"] != "true" || got.Labels["com.docker.compose.service"] != "api" {
		t.Fatalf("Inspect labels = %v, %v", got.Labels, err)
	}
	l, err := c.Labels(ctx, "abc")
	if err != nil || !reflect.DeepEqual(l, got.Labels) {
		t.Fatalf("Labels = %v, %v", l, err)
	}
	if l, err := c.Labels(ctx, "nolabel"); err != nil || l == nil || len(l) != 0 {
		t.Fatalf("no labels must be an empty map, got %v %v", l, err)
	}
	if _, err := c.Labels(ctx, "missing"); err == nil {
		t.Fatal("missing container must be an error")
	}
	list, err := c.List(ctx)
	if err != nil || len(list) != 1 || list[0].Labels["supplyguard.watch"] != "true" {
		t.Fatalf("List labels = %+v, %v", list, err)
	}
}
