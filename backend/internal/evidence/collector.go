// Package evidence collects lightweight forensic evidence from a container right
// before the enforcer kills it: the last log lines, the filesystem diff and the
// process list. No image snapshot (docker commit) by decision [2026-10-20].
package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const (
	// Budget: 전체 수집 시간 상한. 넘으면 모은 것까지만 저장하고 Partial — enforcer 의 훅 예산과 같다
	Budget = 700 * time.Millisecond
	// LogLines · LogBytes: 마지막 200줄, 256KB 상한(뒤쪽을 남긴다)
	LogLines = 200
	LogBytes = 256 << 10
	// MaxChanges: docker diff 항목 상한
	MaxChanges = 500
	// Retention: 보존 기간. 정리는 RunPrune(호출은 main)
	Retention = 7 * 24 * time.Hour

	// logReadLimit: Docker 응답을 읽는 상한(머리말 포함). 200줄이 이보다 길면 앞부분이 잘린 뒤 LogBytes 로 또 자른다
	logReadLimit = int64(LogBytes) * 4
	saveTimeout  = 3 * time.Second
)

// Docker: 수집에 쓰는 읽기 전용 호출. *dockerapi.Client 가 구현한다
type Docker interface {
	Inspect(ctx context.Context, id string) (dockerapi.Container, error)
	Logs(ctx context.Context, id string, tail int, limit int64) ([]byte, error)
	Diff(ctx context.Context, id string) ([]dockerapi.Change, error)
	Top(ctx context.Context, id string) ([]dockerapi.Proc, error)
}

// Store: 증거 저장소. store.Memory · store.Postgres 가 구현한다.
// EvidenceByContainer 는 이름 · 전체 id · 짧은 id(12자 이상 접두)로 찾아 최근 것부터 돌려준다.
type Store interface {
	SaveEvidence(ctx context.Context, e model.Evidence) error
	EvidenceByContainer(ctx context.Context, nameOrID string) ([]model.Evidence, error)
	// PruneEvidence: before 이전 것을 지우고 지운 수를 돌려준다
	PruneEvidence(ctx context.Context, before time.Time) (int, error)
}

type Collector struct {
	Docker Docker
	Store  Store
	// Budget: 0 이면 패키지 기본값
	Budget time.Duration
}

func New(d Docker, s Store) *Collector { return &Collector{Docker: d, Store: s} }

// BeforeKill: enforcer.Docker.BeforeKill 에 그대로 꽂는 훅. 오류는 로그로만 남긴다 (kill 을 막지 않는다)
func (c *Collector) BeforeKill(ctx context.Context, containerID string) {
	ev, err := c.Collect(ctx, containerID)
	switch {
	case err != nil:
		slog.Error("evidence save failed", "id", containerID, "err", err)
	case ev.Partial:
		slog.Warn("evidence collected (partial)", "id", containerID, "name", ev.ContainerName, "ms", ev.DurationMs, "missing", ev.Error)
	default:
		slog.Info("evidence collected", "id", containerID, "name", ev.ContainerName, "ms", ev.DurationMs,
			"logBytes", len(ev.Logs), "changes", len(ev.Changes), "procs", len(ev.Processes))
	}
}

// parts: 고루틴별 결과. mu 아래에서만 읽고 쓴다
type parts struct {
	mu      sync.Mutex
	inspect *dockerapi.Container
	logs    []byte
	changes []dockerapi.Change
	procs   []dockerapi.Proc
	files   []model.EvidenceFile
	// filesOn: 스크립트 읽기를 시작했다(읽을 것이 있고 Docker 가 FileReader 일 때만) — 아니면 빠진 부분으로 세지 않는다
	filesOn bool
	done    map[string]bool
	errs    map[string]error
}

// Collect: 네 가지(inspect · logs · diff · top)를 동시에 모으고 Budget 안에 끝난 것만으로 증거를 만들어 저장한다.
// 반환 오류는 저장 실패뿐 — 수집 오류는 Evidence.Partial · Error 에 남긴다.
func (c *Collector) Collect(ctx context.Context, containerID string) (model.Evidence, error) {
	start := time.Now()
	budget := c.Budget
	if budget <= 0 {
		budget = Budget
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	p := &parts{done: map[string]bool{}, errs: map[string]error{}}
	var wg sync.WaitGroup
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fn()
			p.mu.Lock()
			defer p.mu.Unlock()
			if err != nil {
				p.errs[name] = err
				return
			}
			p.done[name] = true
		}()
	}
	run("inspect", func() error {
		ct, err := c.Docker.Inspect(cctx, containerID)
		if err == nil {
			p.mu.Lock()
			p.inspect = &ct
			p.mu.Unlock()
		}
		return err
	})
	run("logs", func() error {
		b, err := c.Docker.Logs(cctx, containerID, LogLines, logReadLimit)
		if err == nil {
			p.mu.Lock()
			p.logs = b
			p.mu.Unlock()
		}
		return err
	})
	run("diff", func() error {
		ch, err := c.Docker.Diff(cctx, containerID)
		if err == nil {
			p.mu.Lock()
			p.changes = ch
			p.mu.Unlock()
			// 11/10: diff 를 받은 뒤 같은 예산 안에서 설치 스크립트 내용을 읽는다(diff 고루틴이 끝나기 전에 Add — Wait 와 안전)
			if fr, ok := c.Docker.(FileReader); ok {
				if paths := pickScripts(ch); len(paths) > 0 {
					p.mu.Lock()
					p.filesOn = true
					p.mu.Unlock()
					run("files", func() error {
						fs, ferr := readScripts(cctx, fr, containerID, paths)
						p.mu.Lock()
						p.files = fs
						p.mu.Unlock()
						return ferr
					})
				}
			}
		}
		return err
	})
	run("top", func() error {
		pr, err := c.Docker.Top(cctx, containerID)
		if err == nil {
			p.mu.Lock()
			p.procs = pr
			p.mu.Unlock()
		}
		return err
	})
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	select {
	case <-all:
	case <-cctx.Done(): // 예산 끝 — 늦은 고루틴은 ctx 취소로 곧 돌아온다. 지금까지 모은 것으로 만든다
	}

	p.mu.Lock()
	ev := model.Evidence{ID: newID(), ContainerID: containerID, CollectedAt: start.UTC(),
		Changes: []model.FileChange{}, Processes: []model.Proc{}}
	if p.inspect != nil {
		ev.ContainerName, ev.Image = p.inspect.Name, p.inspect.Image
	}
	ev.Logs = tailString(p.logs, LogBytes)
	for i, ch := range p.changes {
		if i >= MaxChanges {
			break
		}
		ev.Changes = append(ev.Changes, model.FileChange{Kind: ch.Kind, Path: ch.Path})
	}
	for _, pr := range p.procs {
		ev.Processes = append(ev.Processes, model.Proc{PID: pr.PID, User: pr.User, Cmd: pr.Cmd})
	}
	ev.Files = append([]model.EvidenceFile(nil), p.files...)
	names := []string{"inspect", "logs", "diff", "top"}
	if p.filesOn {
		names = append(names, "files")
	}
	var missing []string
	for _, name := range names {
		switch {
		case p.done[name]:
		case p.errs[name] != nil:
			missing = append(missing, name+": "+p.errs[name].Error())
		default:
			missing = append(missing, name+": timeout")
		}
	}
	p.mu.Unlock()
	ev.Partial = len(missing) > 0
	ev.Error = strings.Join(missing, "; ")
	ev.DurationMs = int(time.Since(start) / time.Millisecond)

	// 저장은 kill 이 진행돼도 끝낸다 — 훅 ctx 가 끊겨도 되게 취소를 떼고 자체 상한만 둔다
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer scancel()
	if err := c.Store.SaveEvidence(sctx, ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// tailString: 뒤에서 limit 바이트를 남기고, 되도록 줄 머리에서 시작하게 자른다. 깨진 UTF-8 은 치환한다
func tailString(b []byte, limit int) string {
	if len(b) > limit {
		b = b[len(b)-limit:]
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i < len(b)-1 {
			b = b[i+1:]
		}
	}
	return strings.ToValidUTF8(string(b), "�")
}

func newID() string {
	var r [6]byte
	_, _ = rand.Read(r[:])
	return "evd-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(r[:])
}

// RunPrune: 바로 한 번, 그 뒤 interval 마다 Retention 보다 오래된 증거를 지운다. main 이 go 로 띄운다
func RunPrune(ctx context.Context, s Store, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		n, err := s.PruneEvidence(pctx, time.Now().Add(-Retention))
		cancel()
		if err != nil {
			slog.Warn("evidence prune", "err", err)
		} else if n > 0 {
			slog.Info("evidence pruned", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
