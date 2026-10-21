//go:build !linux

package ingestion

import (
	"context"
	"errors"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Gadget: eBPF는 Linux 커널에서만 동작한다. macOS/Windows는 EVENT_SOURCE=mock 사용.
type Gadget struct {
	Kinds         []model.Kind
	ContainerName string
	Discovery     string
	DockerHost    string
	ResolveDNS    bool
}

func (g *Gadget) Run(context.Context, chan<- model.Event) error {
	return errors.New("gadget source requires Linux; set EVENT_SOURCE=mock for local development")
}

// ActiveDiscovery: Linux 가 아니면 컨테이너 컬렉션을 만들지 않으므로 늘 빈 값
func (g *Gadget) ActiveDiscovery() string { return "" }
