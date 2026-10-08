// 런타임 축 관측 에이전트 (docs/13 §3). R-4: ringbuf 소비 + cgroup→컨테이너 매핑 +
// 화이트리스트 1차 필터 + 룰 분류 + SBOM. 의심 이벤트만 남긴다. R-6에서 stdout 대신
// gateway WebSocket으로 업링크한다(현재는 구조화 JSON을 stdout에 낸다).
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	evtExec    = 1
	evtConnect = 2
)

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func emit(v any) {
	b, _ := json.Marshal(v)
	os.Stdout.Write(append(b, '\n'))
}

// dedup — 같은 (키) 이벤트를 짧은 창 안에서 한 번만 통과시킨다. libc의 PATH 탐색이
// 한 번의 셸 스폰에 여러 execve를 내는 소음을 접는다.
type dedup struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newDedup(ttl time.Duration) *dedup { return &dedup{seen: map[string]time.Time{}, ttl: ttl} }

func (d *dedup) first(key string) bool {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.seen[key]; ok && now.Sub(t) < d.ttl {
		return false
	}
	d.seen[key] = now
	if len(d.seen) > 4096 { // 느슨한 상한
		for k, t := range d.seen {
			if now.Sub(t) >= d.ttl {
				delete(d.seen, k)
			}
		}
	}
	return true
}

func main() {
	log.SetFlags(log.Ltime)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	wl, err := loadDefaultWhitelist()
	if err != nil {
		log.Fatalf("whitelist: %v", err)
	}

	dd := newDedup(5 * time.Second)
	up := newUplink(wl)
	resolver := newResolver()
	if err := resolver.refresh(ctx); err != nil {
		log.Printf("warn: initial docker refresh failed: %v (continuing)", err)
	}
	go resolver.run(ctx)

	// agent.hello — 추적 컨테이너 + SBOM (R-6에서 gateway로 전송). 지금은 stdout.
	sbom := resolver.collectSBOM(ctx)
	hello := map[string]any{"type": "agent.hello", "ts": time.Now().UTC(), "containers": []any{}}
	for _, c := range resolver.containers() {
		hello["containers"] = append(hello["containers"].([]any), map[string]any{
			"name": c.Name, "image": c.Image, "sbom": sbom[c.Name],
		})
	}
	emit(hello)
	up.setHello(hello)
	go up.run(ctx)

	var objs spyObjects
	if err := loadSpyObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach execve: %v", err)
	}
	defer tpExec.Close()
	tpConn, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		log.Fatalf("attach connect: %v", err)
	}
	defer tpConn.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	log.Printf("agent ready: tracepoints attached, whitelist loaded, tracking %d container(s)", len(resolver.containers()))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if secs, _ := strconv.Atoi(os.Getenv("AGENT_SMOKE_SECONDS")); secs > 0 {
		go func() { time.Sleep(time.Duration(secs) * time.Second); rd.Close() }()
	}
	go func() { <-stop; log.Printf("shutting down"); cancel(); rd.Close() }()

	var seen, suspicious int
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("done: %d events seen, %d suspicious emitted", seen, suspicious)
				return
			}
			continue
		}
		var e spyEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		seen++
		if handleEvent(wl, resolver, dd, up, &e) {
			suspicious++
		}
	}
}

// handleEvent: 컨테이너 매핑 → 화이트리스트 필터 → 룰 분류. 의심이면 emit하고 true.
func handleEvent(wl *Whitelist, resolver *Resolver, dd *dedup, up *Uplink, e *spyEvent) bool {
	c, ok := resolver.lookup(e.CgroupId)
	if !ok {
		return false // 추적 대상(carrot-*) 아님 → 버림
	}
	comm := cstr(e.Comm[:])

	switch e.Type {
	case evtExec:
		file := cstr(e.Filename[:])
		rule := wl.classifyExec(comm, file)
		if rule == "" || !dd.first(c.Name+"|"+strconv.Itoa(int(e.Pid))+"|"+rule) {
			return false
		}
		ev := map[string]any{
			"type": "runtime.event", "rule": rule, "kind": "exec",
			"container": c.Name, "image": c.Image,
			"pid": e.Pid, "ppid": e.Ppid, "comm": comm, "file": file,
			"ts": time.Now().UTC(),
		}
		emit(ev)
		up.event(ev)
		log.Printf("[%s] %-22s %s pid=%d ppid=%d comm=%s file=%s", c.Name, rule, "exec", e.Pid, e.Ppid, comm, file)
		return true

	case evtConnect:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], e.Daddr)
		dst := netip.AddrFrom4(b)
		rule := wl.classifyConnect(dst, e.Dport)
		if rule == "" || !dd.first(c.Name+"|"+strconv.Itoa(int(e.Pid))+"|"+rule+"|"+dst.String()) {
			return false
		}
		ev := map[string]any{
			"type": "runtime.event", "rule": rule, "kind": "connect",
			"container": c.Name, "image": c.Image,
			"pid": e.Pid, "ppid": e.Ppid, "comm": comm,
			"dst_ip": dst.String(), "dst_port": e.Dport,
			"ts": time.Now().UTC(),
		}
		emit(ev)
		up.event(ev)
		log.Printf("[%s] %-22s connect pid=%d comm=%s dst=%s:%d", c.Name, rule, e.Pid, comm, dst.String(), e.Dport)
		return true
	}
	return false
}
