package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Container — 추적 대상 컨테이너(토폴로지 노드 키).
type Container struct {
	ID    string
	Name  string
	Image string
}

// 추적 대상 접두사. carrot-* 모사 서비스만 관측·업링크한다(docs/13 §12 대상 한정).
const trackedPrefix = "carrot-"

// Resolver — cgroup id → 추적 컨테이너 매핑. Docker API(unix 소켓) + cgroupfs inode 조회로 캐시.
type Resolver struct {
	http       *http.Client
	cgroupRoot string

	mu      sync.RWMutex
	byCID   map[string]*Container // containerID → meta
	byCg    map[uint64]*Container // cgroup id(inode) → meta
	byName  map[string]*Container
}

func newResolver() *Resolver {
	sock := os.Getenv("DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	root := os.Getenv("CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	return &Resolver{
		http: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}},
		cgroupRoot: root,
		byCID:      map[string]*Container{},
		byCg:       map[uint64]*Container{},
		byName:     map[string]*Container{},
	}
}

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
}

func (r *Resolver) dockerGET(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// refresh — Docker에서 carrot-* 컨테이너 목록을 받아 cgroup inode와 매핑한다.
func (r *Resolver) refresh(ctx context.Context) error {
	var list []dockerContainer
	if err := r.dockerGET(ctx, "/containers/json", &list); err != nil {
		return err
	}
	byCID := map[string]*Container{}
	byName := map[string]*Container{}
	for _, dc := range list {
		name := ""
		for _, n := range dc.Names {
			name = strings.TrimPrefix(n, "/")
			break
		}
		if !strings.HasPrefix(name, trackedPrefix) {
			continue
		}
		c := &Container{ID: dc.ID, Name: name, Image: dc.Image}
		byCID[dc.ID] = c
		byName[name] = c
	}
	// cgroupfs를 훑어 추적 컨테이너 id가 경로에 든 디렉터리의 inode를 cgroup id로 매핑.
	byCg := map[uint64]*Container{}
	_ = filepath.WalkDir(r.cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		for id, c := range byCID {
			if strings.Contains(d.Name(), id) || strings.Contains(d.Name(), id[:min(12, len(id))]) {
				if fi, e := os.Stat(p); e == nil {
					if st, ok := fi.Sys().(*syscall.Stat_t); ok {
						byCg[st.Ino] = c
					}
				}
			}
		}
		return nil
	})
	r.mu.Lock()
	r.byCID, r.byName, r.byCg = byCID, byName, byCg
	r.mu.Unlock()
	return nil
}

func (r *Resolver) lookup(cgroupID uint64) (*Container, bool) {
	r.mu.RLock()
	c, ok := r.byCg[cgroupID]
	r.mu.RUnlock()
	return c, ok
}

func (r *Resolver) containers() []*Container {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Container, 0, len(r.byName))
	for _, c := range r.byName {
		out = append(out, c)
	}
	return out
}

// run — 주기적으로 매핑을 갱신(컨테이너 재기동·cgroup 변동 대응).
func (r *Resolver) run(ctx context.Context) {
	_ = r.refresh(ctx)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.refresh(ctx)
		}
	}
}
