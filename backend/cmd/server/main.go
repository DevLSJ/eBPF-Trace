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
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/pipeline"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/stats"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/store"
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
	var buffer store.Buffer = mem
	checks := map[string]api.Pinger{}
	if cfg.DatabaseURL != "" {
		pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer pg.Close()
		policies, audit, checks["postgres"] = pg, pg, pg
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

	// 이벤트 소스와 격리 수단
	var source ingestion.Source
	var enf enforcer.Enforcer
	switch cfg.EventSource {
	case "mock":
		m := ingestion.NewMock()
		source, enf = m, m
	default:
		source = &ingestion.Gadget{Kinds: cfg.Gadgets, ContainerName: cfg.ContainerName}
		if enf, err = enforcer.NewDocker(cfg.DockerHost); err != nil {
			return err
		}
	}

	hub := ws.NewHub(cfg.AllowedOrigins)
	agg := stats.New()
	pipe := pipeline.New(pipeline.Options{
		EnforceKill:      cfg.EnforceKill,
		IgnoreContainers: cfg.IgnoreContainers,
		NormalEventRate:  cfg.NormalEventRate,
	}, engine, enf, hub, agg, audit, buffer)

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
		AllowAnonymousWrites: cfg.AdminToken == "" && cfg.EventSource == "mock",
		Info: api.Info{Source: cfg.EventSource, Gadgets: cfg.Gadgets, EnforceKill: cfg.EnforceKill,
			GadgetVersion: ingestion.GadgetVersion},
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
		"gadgets", cfg.Gadgets, "enforceKill", cfg.EnforceKill, "ignore", strings.Join(cfg.IgnoreContainers, ","))
	if cfg.AdminToken == "" && cfg.EventSource != "mock" {
		slog.Warn("ADMIN_TOKEN not set; policy changes are disabled")
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
