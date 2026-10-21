package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipLimiter: IP 별 최근 window 안의 실패 횟수가 max 에 닿으면 막는다 (프로세스 메모리, 단일 호스트 전제)
type ipLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
	calls  int
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{window: window, max: max, hits: map[string][]time.Time{}}
}

func (l *ipLimiter) recent(ip string, now time.Time) []time.Time {
	hs := l.hits[ip]
	i := 0
	for i < len(hs) && now.Sub(hs[i]) >= l.window {
		i++
	}
	hs = hs[i:]
	if len(hs) == 0 {
		delete(l.hits, ip)
	} else {
		l.hits[ip] = hs
	}
	return hs
}

// Allow: 지금 시도해도 되는지 (실패 기록은 Fail 로 따로 남긴다)
func (l *ipLimiter) Allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, now)) < l.max
}

func (l *ipLimiter) Fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[ip] = append(l.recent(ip, now), now)
	// 가끔 오래된 IP 를 지운다 (메모리 상한)
	if l.calls++; l.calls%256 == 0 {
		for k := range l.hits {
			l.recent(k, now)
		}
	}
}

// ClientIP: trustProxy 면 X-Real-IP → X-Forwarded-For 첫 값, 아니면 연결 주소.
// 백엔드 포트가 바깥에 열려 있으면 머리글을 위조할 수 있으므로 nginx 뒤에서만 trustProxy 를 켠다.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			first, _, _ := strings.Cut(v, ",")
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
