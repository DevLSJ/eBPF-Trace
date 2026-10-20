// Command server is the SupplyGuard backend: gadget ingestion, rule evaluation,
// Docker isolation, REST API and the dashboard WebSocket on one port (:8000).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/api"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/config"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/osv"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/review"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/scan"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/summary"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ws"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()})))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		return slog.LevelInfo
	}
	return l
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 저장소: DATABASE_URL·REDIS_URL이 없으면 메모리 (로컬 개발)
	mem := store.NewMemory()
	var policies store.PolicyStore = mem
	var audit store.AuditStore = mem
	var reviewStore store.ReviewStore = mem
	var buffer store.Buffer = mem
	var collected store.CollectedStore = mem
	checks := map[string]api.Pinger{}
	if cfg.DatabaseURL != "" {
		pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer pg.Close()
		policies, audit, reviewStore, collected, checks["postgres"] = pg, pg, pg, pg, pg
	}
	if cfg.RedisURL != "" {
		rd, err := store.NewRedis(ctx, cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer rd.Close()
		buffer, checks["redis"] = rd, rd
	}

	rs, err := initialPolicies(ctx, policies, cfg.PolicyFile)
	if err != nil {
		return err
	}
	engine := rules.New(rs)
	slog.Info("policies loaded", "count", len(rs))

	// 이벤트 소스와 격리 수단. lifecycle: 컨테이너 시작 · 종료(차단 이미지 격리 · 설치 세션 종료 시각)
	var source, lifecycle ingestion.Source
	var enf enforcer.Enforcer
	var onInstallStart func(model.InstallSession)
	switch cfg.EventSource {
	case "mock":
		m := ingestion.NewMock()
		source, enf, onInstallStart = m, m, m.SimulateInstall
	default:
		source = &ingestion.Gadget{Kinds: cfg.Gadgets, ContainerName: cfg.ContainerName, Discovery: cfg.ContainerDiscovery, DockerHost: cfg.DockerHost, ResolveDNS: cfg.ResolveDNS}
		lifecycle = &ingestion.DockerLifecycle{DockerHost: cfg.DockerHost}
		if enf, err = enforcer.NewDocker(cfg.DockerHost); err != nil {
			return err
		}
	}

	hub := ws.NewHub(cfg.AllowedOrigins)

	// 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력. 엔진에는 저장된 정책 + 차단 도메인 시스템 규칙(blocklist-hosts)
	rv := review.New(review.Options{
		Store: reviewStore, Policies: policies, Audit: audit, Engine: engine, Hub: hub,
		Actor: cfg.ActorName, EnforceKill: cfg.EnforceKill, OnInstallStart: onInstallStart,
	})
	if err := rv.Load(ctx); err != nil {
		return fmt.Errorf("review load: %w", err)
	}
	if err := rv.Reload(ctx); err != nil {
		return fmt.Errorf("review reload: %w", err)
	}
	go rv.Run(ctx)
	agg := stats.New()
	// 종합(10/16): 1분 단위 수집량을 10초마다 저장소에 더한다. 끝날 때 한 번 더
	go flushCollected(ctx, agg, collected)
	// 공급망 검사(10/16): Docker 로 검사기 컨테이너를 띄운다. 결과는 정책 · 감사와 같은 저장소(PG 면 scans 테이블)
	var scanStore scan.Store = mem
	if pgScans, ok := reviewStore.(scan.Store); ok {
		scanStore = pgScans
	}
	var scans *scan.Service
	if dc, err := dockerapi.New(cfg.DockerHost); err != nil {
		slog.Warn("scan disabled: docker", "err", err)
	} else {
		scans = scan.New(scan.Options{Docker: dc, Dir: cfg.ScanDir, Volume: cfg.ScanVolume, GuardDogImage: cfg.GuardDogImage, OSVImage: cfg.OSVImage, Store: scanStore, Blocker: rv})
		if err := scans.Load(ctx); err != nil {
			slog.Warn("scan load", "err", err)
		}
	}
	pipe := pipeline.New(pipeline.Options{
		EnforceKill:      cfg.EnforceKill,
		IgnoreContainers: cfg.IgnoreContainers,
		WatchContainers:  cfg.WatchContainers,
		NormalEventRate:  cfg.NormalEventRate,
	}, engine, enf, hub, agg, audit, buffer)
	pipe.SetReview(rv)

	snapshot := func() stats.Snapshot {
		s := agg.Snapshot()
		s.WSClients, s.Dropped = hub.Clients(), hub.Dropped()
		s.EnforceKill, s.Source = cfg.EnforceKill, cfg.EventSource
		return s
	}

	events := make(chan model.Event, cfg.EventBuffer)
	go func() {
		if err := source.Run(ctx, events); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("event source stopped", "source", cfg.EventSource, "err", err)
			stop() // 수집이 죽은 채로 떠 있으면 탐지가 조용히 멈춘다 — 재시작에 맡긴다
		}
	}()
	if lifecycle != nil {
		go func() {
			if err := lifecycle.Run(ctx, events); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("container lifecycle source stopped", "err", err)
			}
		}()
	}
	go pipe.Run(ctx, events)
	go func() {
		t := time.NewTicker(cfg.StatsInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				hub.Broadcast("stats", snapshot())
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/events", hub.HandleWS)
	mux.Handle("/", api.Router(api.Deps{
		Engine: engine, Policies: policies, Audit: audit, Buffer: buffer,
		Stats: snapshot, Checks: checks,
		AdminToken:           cfg.AdminToken,
		SandboxToken:         cfg.SandboxToken,
		AllowAnonymousWrites: cfg.EventSource == "mock", // 비어 있는 토큰만 익명 허용 (정한 토큰은 mock 이어도 검사)
		Review:               rv,
		Summary:              summary.New(audit, collected, reviewView{rv}),
		Scans:                scans,
		OSV:                  osv.New(),
		AllowedOrigins:       cfg.AllowedOrigins,
		Info: api.Info{Source: cfg.EventSource, Gadgets: cfg.Gadgets, EnforceKill: cfg.EnforceKill,
			GadgetVersion: ingestion.GadgetVersion, WatchContainers: cfg.WatchContainers, IgnoreContainers: cfg.IgnoreContainers},
	}))

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		hub.Close()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	slog.Info("listening", "addr", srv.Addr, "source", cfg.EventSource,
		"gadgets", cfg.Gadgets, "enforceKill", cfg.EnforceKill, "ignore", strings.Join(cfg.IgnoreContainers, ","), "watch", strings.Join(cfg.WatchContainers, ","))
	if cfg.EventSource == "gadget" && cfg.EnforceKill && len(cfg.WatchContainers) == 0 {
		slog.Warn("ENFORCE_KILL=true without WATCH_CONTAINERS: every container on this host can be killed by policy")
	}
	if cfg.AdminToken == "" && cfg.EventSource != "mock" {
		slog.Warn("ADMIN_TOKEN not set; policy changes and verdicts are disabled")
	}
	if cfg.SandboxToken == "" && cfg.EventSource != "mock" {
		slog.Warn("SANDBOX_TOKEN not set; sg-install session reports and blocklist checks are disabled")
	}
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// initialPolicies: 저장소가 비어 있으면 POLICY_FILE로 한 번 시드한다.
func initialPolicies(ctx context.Context, ps store.PolicyStore, file string) ([]rules.Rule, error) {
	rs, err := ps.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) > 0 {
		return rs, nil
	}
	seed, err := rules.LoadFile(file)
	if err != nil {
		return nil, fmt.Errorf("POLICY_FILE %s: %w", file, err)
	}
	if err := ps.ReplacePolicies(ctx, seed); err != nil {
		return nil, err
	}
	slog.Info("policies seeded", "file", file, "count", len(seed))
	return seed, nil
}

// flushCollected: 통계의 1분 단위 수집량을 저장소로 옮긴다(같은 분은 저장소가 더한다)
func flushCollected(ctx context.Context, agg *stats.Aggregator, st store.CollectedStore) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	flush := func(ctx context.Context) {
		if ms := agg.TakeMinutes(); len(ms) > 0 {
			if err := st.AddCollected(ctx, ms); err != nil {
				slog.Warn("collected flush", "err", err, "minutes", len(ms))
			}
		}
	}
	for {
		select {
		case <-t.C:
			flush(ctx)
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			flush(fctx)
			cancel()
			return
		}
	}
}

// reviewView: 종합이 읽는 설치 세션 · 건 · 차단 목록
type reviewView struct{ rv *review.Service }

func (v reviewView) Installs() []model.InstallSession {
	return v.rv.ListInstalls(review.InstallQuery{Limit: 500})
}
func (v reviewView) Cases() []model.Case        { return v.rv.ListCases(review.CaseQuery{}) }
func (v reviewView) Blocklist() model.Blocklist { return v.rv.Blocklist() }
