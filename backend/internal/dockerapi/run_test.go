package dockerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Tier 2 — 공급망 검사기 마운트(11/06): 이름 있는 볼륨(컨테이너 스택)은 그대로 volume,
// 절대 경로(make dev — 백엔드가 맥에서 직접 돌 때 SCAN_VOLUME=SCAN_DIR)는 그 폴더를 bind. 둘 다 읽기 전용
func TestRunMounts(t *testing.T) {
	for _, tc := range []struct {
		name, volume string
		want         map[string]any
	}{
		{"이름 있는 볼륨", "supplyguard_scan_work", map[string]any{"Type": "volume", "Source": "supplyguard_scan_work", "Target": "/work", "ReadOnly": true}},
		{"절대 경로", "/Users/me/sg/.scan-work", map[string]any{"Type": "bind", "Source": "/Users/me/sg/.scan-work", "Target": "/work", "ReadOnly": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created struct {
				HostConfig struct{ Mounts []map[string]any }
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/containers/create":
					_ = json.NewDecoder(r.Body).Decode(&created)
					w.WriteHeader(201)
					_, _ = w.Write([]byte(`{"Id":"cid1"}`))
				case r.URL.Path == "/containers/cid1/wait":
					_, _ = w.Write([]byte(`{"StatusCode":0}`))
				default:
					w.WriteHeader(204)
				}
			}))
			defer srv.Close()
			c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.Run(context.Background(), RunSpec{Name: "x", Image: "img", Volume: tc.volume, Target: "/work"}); err != nil {
				t.Fatal(err)
			}
			if len(created.HostConfig.Mounts) != 1 || !reflect.DeepEqual(created.HostConfig.Mounts[0], tc.want) {
				t.Fatalf("Mounts = %v, want [%v]", created.HostConfig.Mounts, tc.want)
			}
		})
	}
}
