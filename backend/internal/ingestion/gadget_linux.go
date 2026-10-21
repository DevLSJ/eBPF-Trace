//go:build linux

package ingestion

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/btfgen"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cgroup"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/filter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/process"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/uidgidresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm" // trace_dns 등 WASM 레이어가 있는 가젯의 CO-RE 재배치에 필요
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// Gadget: 1단계의 `ig run <gadget> --runtimes=docker [--containername=...]`를
// Go 패키지로 옮긴 것. 가젯마다 gadget context 하나, 런타임·localmanager는 공유한다.
type Gadget struct {
	Kinds         []model.Kind
	ContainerName string
	// Discovery: 설정값 "auto"(기본, fanotify 먼저 → 안 되면 docker-events) | "fanotify"(IG 기본 runc 훅) | "docker-events"(Docker 이벤트 API)
	Discovery  string
	DockerHost string
	// ResolveDNS: connect 가 켜져 있으면 trace_dns 도 함께 돌려 목적지 도메인을 배운다
	ResolveDNS bool
	dropped    atomic.Uint64
	// active: Run 이 실제로 만든 컨테이너 컬렉션 방식(DiscoveryFanotify | DiscoveryDockerEvents). Run 전에는 빈 값
	active atomic.Value
}

// ActiveDiscovery: 실제로 쓰이는 컨테이너 발견 방식 — /api/info discovery 가 쓴다. Run 이 컬렉션을 만들기 전에는 빈 값
func (g *Gadget) ActiveDiscovery() string {
	s, _ := g.active.Load().(string)
	return s
}

// collection: 컨테이너 컬렉션을 감싼 LocalManager 와 그 정리 함수
type collection struct {
	lm    operators.DataOperator
	close func()
}

const opPriority = 50000

func (g *Gadget) Run(ctx context.Context, out chan<- model.Event) error {
	// 컨테이너 안에서 돌 때(HOST_ROOT=/host) bpffs·debugfs·tracefs가 없으면 마운트
	if err := host.Init(host.Config{AutoMountFilesystems: true}); err != nil {
		return fmt.Errorf("host init: %w", err)
	}
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer rt.Close()

	// 컨테이너 메타데이터 부착 (docker). host.Init 이후에 초기화해야 한다.
	// auto: fanotify 컬렉션 생성이 실패하면(Docker Desktop EINVAL 등) docker-events 로 내려간다 — 판정은 생성 단계 오류로만
	fanotify := func() (collection, error) {
		fc, err := newFanotifyCollection(g.DockerHost)
		if err != nil {
			return collection{}, err
		}
		return collection{localmanager.NewLocalManager(&fc.cc, fc.tc), fc.Close}, nil
	}
	dockerEvents := func() (collection, error) {
		dc, err := newDockerCollection(ctx, g.DockerHost)
		if err != nil {
			return collection{}, err
		}
		return collection{localmanager.NewLocalManager(&dc.cc, dc.tc), dc.Close}, nil
	}
	col, active, err := pickDiscovery(g.Discovery, fanotify, dockerEvents, func(err error) {
		slog.Warn("container discovery: fanotify unavailable, falling back to docker-events", "err", err)
	})
	if err != nil {
		return err
	}
	defer col.close()
	lm := col.lm
	g.active.Store(active)
	if active == DiscoveryDockerEvents {
		slog.Info("container discovery", "mode", active, "requested", g.Discovery, "note", "actions in the first ~0.1s after a container starts may be missed")
	} else {
		slog.Info("container discovery", "mode", active, "requested", g.Discovery)
	}

	// ig 와 동일하게 등록된 데이터 오퍼레이터 전체를 쓰되, 기본 LocalManager 는 제외하고
	// 위에서 만든 컨테이너 컬렉션(lm)으로 대체한다. trace_dns 같은 소켓필터 가젯이 socketenricher 등
	// 다른 오퍼레이터가 제공하는 심볼을 CO-RE 로 참조하므로, 세트가 빠지면 로드가 깨진다.
	shared := []operators.DataOperator{ocihandler.OciHandler, lm}
	for name, op := range operators.GetDataOperators() {
		if name == localmanager.OperatorName {
			continue // 기본 대신 lm 사용
		}
		if err := op.Init(apihelpers.ToParamDescs(op.GlobalParams()).ToParams()); err != nil {
			slog.Warn("skipping data operator (init failed)", "op", name, "err", err)
			continue
		}
		shared = append(shared, op)
	}

	go g.reportDrops(ctx)

	kinds := append([]model.Kind{}, g.Kinds...)
	if g.ResolveDNS && slices.Contains(kinds, model.KindConnect) {
		kinds = append(kinds, model.KindDNS)
	}
	var wg sync.WaitGroup
	for _, k := range kinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.runWithRetry(ctx, rt, shared, k, out)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// runWithRetry: 이미지 pull 실패 등으로 가젯이 멈추면 백오프 후 다시 띄운다.
// trace_dns 는 목적지 도메인 부가정보용 보조 가젯이라, 로드에 반복 실패하면
// 몇 번 시도 후 조용히 포기한다 — connect/open/exec 탐지는 그대로 돈다.
func (g *Gadget) runWithRetry(ctx context.Context, rt *local.Runtime, shared []operators.DataOperator, k model.Kind, out chan<- model.Event) {
	backoff := time.Second
	quickFails := 0
	for ctx.Err() == nil {
		start := time.Now()
		slog.Info("gadget starting", "kind", k, "image", GadgetImage[k])
		err := g.runOne(ctx, rt, shared, k, out)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) < 10*time.Second {
			quickFails++
		} else {
			quickFails, backoff = 0, time.Second
		}
		if k == model.KindDNS && quickFails >= 3 {
			slog.Warn("trace_dns gadget failed to load; destination domains disabled (exec/open/connect detection unaffected)", "err", err)
			return
		}
		slog.Error("gadget stopped; retrying", "kind", k, "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (g *Gadget) runOne(ctx context.Context, rt *local.Runtime, shared []operators.DataOperator, k model.Kind, out chan<- model.Event) error {
	consumer := simple.New("supplyguard-consumer-"+string(k),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				if err := g.subscribe(d, k, out); err != nil {
					return err
				}
			}
			return nil
		}),
	)
	gctx := gadgetcontext.New(ctx, GadgetImage[k],
		gadgetcontext.WithDataOperators(append(append([]operators.DataOperator{}, shared...), consumer)...),
	)
	params := map[string]string{}
	if g.ContainerName != "" {
		params["operator.LocalManager.containername"] = g.ContainerName
	}
	if k == model.KindConnect {
		params["operator.oci.ebpf.connect-only"] = "true"
	}
	err := rt.RunGadget(gctx, nil, params)
	if err == nil {
		err = errors.New("gadget exited")
	}
	return err
}

// subscribe: 필드 이름은 `ig run <gadget> -o json` 출력 키와 같다.
func (g *Gadget) subscribe(d datasource.DataSource, k model.Kind, out chan<- model.Event) error {
	commF := d.GetField("proc.comm")
	pidF := d.GetField("proc.pid")
	cNameF := d.GetField("runtime.containerName")
	cIDF := d.GetField("runtime.containerId")
	imgF := d.GetField("runtime.containerImageName")
	argsF := d.GetField("args")        // exec
	fnameF := d.GetField("fname")      // open
	dstAddrF := d.GetField("dst.addr") // connect (l4endpoint → addr/port)
	dstPortF := d.GetField("dst.port") // connect
	nameF := d.GetField("name")        // dns
	addrsF := d.GetField("addresses")  // dns (응답에만, 콤마 구분)
	if commF == nil || cIDF == nil {
		return fmt.Errorf("datasource %q: proc.comm/runtime.containerId 필드 없음", d.Name())
	}

	str := func(f datasource.FieldAccessor, data datasource.Data) string {
		if f == nil {
			return ""
		}
		s, _ := f.String(data)
		return s
	}

	return d.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		ev := model.Event{
			Kind:          k,
			Timestamp:     time.Now().UTC(),
			ContainerID:   str(cIDF, data),
			ContainerName: str(cNameF, data),
			ImageName:     str(imgF, data),
			Comm:          str(commF, data),
		}
		if pidF != nil {
			ev.Pid, _ = pidF.Uint32(data)
		}
		switch k {
		case model.KindExec:
			if argsF != nil {
				b, _ := argsF.Bytes(data)
				ev.Args = cleanArgs(b)
			}
		case model.KindOpen:
			ev.Path = str(fnameF, data)
		case model.KindConnect:
			ev.DstIP = str(dstAddrF, data)
			if dstPortF != nil {
				ev.DstPort, _ = dstPortF.Uint16(data)
			}
		case model.KindDNS:
			addrs := str(addrsF, data)
			if addrs == "" {
				return nil // 질의 패킷: 배울 것이 없다
			}
			ev.DNSName = str(nameF, data)
			ev.DNSAddrs = strings.Split(addrs, ",")
		}
		if !send(out, ev) {
			g.dropped.Add(1)
		}
		return nil
	}, opPriority)
}

func (g *Gadget) reportDrops(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := g.dropped.Load(); n != last {
				slog.Warn("events dropped by backpressure", "total", n, "since_last", n-last)
				last = n
			}
		}
	}
}
