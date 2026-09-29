// Package ingestion turns kernel events into model.Event values on a channel.
// The real source runs Inspektor Gadget gadgets in-process (Linux, root);
// the mock source replays demo scenarios for local development.
package ingestion

import (
	"context"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Source: out 채널로 정규화 이벤트를 보내고, ctx가 끝나면 반환한다.
type Source interface {
	Run(ctx context.Context, out chan<- model.Event) error
}

// GadgetImage: Kind → 공식 가젯 OCI 이미지. 버전은 go.mod의 IG 라이브러리 버전과 같게 유지한다.
// sys_connect는 trace_tcpconnect가 trace_tcp(connect-only)로 통합되어 trace_tcp를 쓴다.
var GadgetImage = map[model.Kind]string{
	model.KindExec:    "ghcr.io/inspektor-gadget/gadget/trace_exec:" + GadgetVersion,
	model.KindOpen:    "ghcr.io/inspektor-gadget/gadget/trace_open:" + GadgetVersion,
	model.KindConnect: "ghcr.io/inspektor-gadget/gadget/trace_tcp:" + GadgetVersion,
	// trace_dns: connect 이벤트에 목적지 도메인을 붙이기 위한 보조 가젯 (RESOLVE_DNS)
	model.KindDNS: "ghcr.io/inspektor-gadget/gadget/trace_dns:" + GadgetVersion,
}

const GadgetVersion = "v0.56.1"

// cleanArgs: argv가 NUL로 구분되어 오는 경우를 대비해 공백으로 합친다.
func cleanArgs(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", " "))
}

// send: 소비가 밀리면 드롭한다 (1차 백프레셔는 채널 버퍼).
func send(out chan<- model.Event, ev model.Event) bool {
	select {
	case out <- ev:
		return true
	default:
		return false
	}
}
