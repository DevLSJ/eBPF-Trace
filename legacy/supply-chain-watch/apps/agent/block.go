package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Enforcer — 역방향 제어 (docs/13 §7). 악성 프로세스 그룹 SIGKILL + eBPF 목적지 차단.
type Enforcer struct {
	blocked *ebpf.Map

	mu      sync.Mutex
	pids    map[string]map[int]time.Time // container → 악성 프로세스(심어진 루프) pid
	links   []link.Link
	cgDirOf func(container string) string // 컨테이너 → cgroup 디렉터리(cgroup.procs 스캔용)
}

func newEnforcer(blocked *ebpf.Map) *Enforcer {
	return &Enforcer{blocked: blocked, pids: map[string]map[int]time.Time{}}
}

// remember — PROC_CHAIN(앱 런타임이 띄운 셸 루프) pid를 컨테이너별로 기억한다.
func (e *Enforcer) remember(container string, pid int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pids[container] == nil {
		e.pids[container] = map[int]time.Time{}
	}
	e.pids[container][pid] = time.Now()
}

// kill — 해당 컨테이너의 악성 프로세스 그룹만 SIGKILL. 서비스 본체(node/uvicorn=PID1)는 유지.
func (e *Enforcer) kill(container string) string {
	pids := map[int]bool{}
	e.mu.Lock()
	for p := range e.pids[container] {
		pids[p] = true
	}
	delete(e.pids, container)
	e.mu.Unlock()

	// cgroup.procs를 스캔해 비콘 프로세스(심어진 루프·curl)를 보강한다. 세션과 무관하게 찾는다.
	if e.cgDirOf != nil {
		if dir := e.cgDirOf(container); dir != "" {
			if data, err := os.ReadFile(dir + "/cgroup.procs"); err == nil {
				for _, f := range strings.Fields(string(data)) {
					pid, perr := strconv.Atoi(f)
					if perr != nil || pid <= 1 {
						continue
					}
					cl, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					if rerr != nil {
						continue
					}
					cmd := string(bytes.ReplaceAll(cl, []byte{0}, []byte{' '}))
					if strings.Contains(cmd, "fake-c2") || strings.Contains(cmd, "while true") {
						pids[pid] = true
					}
				}
			}
		}
	}

	killed := 0
	for pid := range pids {
		// 음수 pid = 프로세스 그룹(심어진 sh 루프 + 그 curl 자식). 루프는 detached로 그룹 리더.
		if err := unix.Kill(-pid, unix.SIGKILL); err == nil {
			killed++
		} else if err := unix.Kill(pid, unix.SIGKILL); err == nil {
			killed++
		}
	}
	log.Printf("[kill] container=%s killed=%d", container, killed)
	return fmt.Sprintf("SIGKILL 전송 · 악성 프로세스 %d개 종료", killed)
}

// block — 목적지 IPv4를 eBPF 차단 맵에 넣는다. 이후 그 목적지로의 connect는 커널에서 거부된다.
func (e *Enforcer) block(ipStr string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return "잘못된 IP"
	}
	b := addr.As4()
	key := binary.LittleEndian.Uint32(b[:]) // user_ip4(network order 바이트)의 CPU 해석과 일치
	if err := e.blocked.Put(key, uint8(1)); err != nil {
		return "차단 맵 기록 실패: " + err.Error()
	}
	log.Printf("[block] dest=%s added to eBPF blocklist", ipStr)
	return "목적지 차단 · " + ipStr
}

// attachConnect4 — carrot 컨테이너 cgroup마다 connect4 차단 프로그램을 부착한다.
func (e *Enforcer) attachConnect4(prog *ebpf.Program, dirs map[string]string) {
	for name, dir := range dirs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    dir,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: prog,
		})
		if err != nil {
			log.Printf("[block] connect4 attach %s failed: %v", name, err)
			continue
		}
		e.links = append(e.links, l)
		log.Printf("[block] connect4 attached to %s", name)
	}
}

func (e *Enforcer) close() {
	for _, l := range e.links {
		_ = l.Close()
	}
}
