package pipeline

import (
	"strings"
	"sync"
	"time"
)

// Resolver: trace_dns 응답으로 (컨테이너, IP) → 도메인을 기억해 connect 이벤트에 목적지 이름을 붙인다.
// 컨테이너별로 먼저 찾고, 없으면 호스트 전체에서 최근 응답을 찾는다(같은 CDN IP 를 여러 컨테이너가 조회하는 경우).
type Resolver struct {
	mu     sync.Mutex
	byCtr  map[string]map[string]dnsEntry // containerID → ip → entry
	global map[string]dnsEntry
	ttl    time.Duration
	last   time.Time
}

type dnsEntry struct {
	host string
	at   time.Time
}

const resolverMaxPerContainer = 4096

func NewResolver(ttl time.Duration) *Resolver {
	return &Resolver{byCtr: map[string]map[string]dnsEntry{}, global: map[string]dnsEntry{}, ttl: ttl}
}

// Learn: DNS 응답 한 건 (name → addrs)
func (r *Resolver) Learn(containerID, name string, addrs []string, now time.Time) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if host == "" || len(addrs) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.byCtr[containerID]
	if m == nil {
		m = map[string]dnsEntry{}
		r.byCtr[containerID] = m
	}
	if len(m) >= resolverMaxPerContainer {
		r.pruneLocked(now, true)
	}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		m[a] = dnsEntry{host: host, at: now}
		r.global[a] = dnsEntry{host: host, at: now}
	}
	if now.Sub(r.last) > time.Minute {
		r.pruneLocked(now, false)
	}
}

// Lookup: 컨테이너가 최근 조회한 이름, 없으면 호스트 전체 기준. 모르면 "".
func (r *Resolver) Lookup(containerID, ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if e, ok := r.byCtr[containerID][ip]; ok && now.Sub(e.at) <= r.ttl {
		return e.host
	}
	if e, ok := r.global[ip]; ok && now.Sub(e.at) <= r.ttl {
		return e.host
	}
	return ""
}

// Forget: 컨테이너가 사라지면 그 캐시도 버린다 (새 ID 로 재기동하므로 누적 방지)
func (r *Resolver) Forget(containerID string) {
	r.mu.Lock()
	delete(r.byCtr, containerID)
	r.mu.Unlock()
}

func (r *Resolver) pruneLocked(now time.Time, force bool) {
	r.last = now
	for id, m := range r.byCtr {
		for ip, e := range m {
			if now.Sub(e.at) > r.ttl || (force && len(m) >= resolverMaxPerContainer) {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(r.byCtr, id)
		}
	}
	for ip, e := range r.global {
		if now.Sub(e.at) > r.ttl {
			delete(r.global, ip)
		}
	}
}
