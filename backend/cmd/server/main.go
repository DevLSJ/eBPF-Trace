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
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/auth"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/chat"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/config"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/demo"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/dockerapi"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/enforcer"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/evidence"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/ingestion"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/integration"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/notify"
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
	var evStore evidence.Store = mem
	var authStore store.AuthStore = store.NewMemoryAuth() // 계정 · 세션 · 라이선스 · 인증 감사 (메모리면 재시작 때 사라진다)
	checks := map[string]api.Pinger{}
	if cfg.DatabaseURL != "" {
		pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer pg.Close()
		if err := pg.EnsureEvidenceSchema(ctx); err != nil {
			return fmt.Errorf("postgres evidence: %w", err)
		}
		policies, audit, reviewStore, collected, evStore, checks["postgres"] = pg, pg, pg, pg, pg, pg
		if err := pg.MigrateAuth(ctx); err != nil {
			return fmt.Errorf("postgres auth migrate: %w", err)
		}
		authStore = pg
	}
	go evidence.RunPrune(ctx, evStore, time.Hour) // 증거 보존 7일
	if cfg.RedisURL != "" {
		rd, err := store.NewRedis(ctx, cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer rd.Close()
		buffer, checks["redis"] = rd, rd
	}

	// 로그인(10/20). 가젯(운영)은 OTP 비밀값 암호화 키 없이 시작하지 않는다 — 가젯 · 수집을 띄우기 전에 확인
	if err := validateAuthSecret(cfg.EventSource, cfg.AuthSecretKey); err != nil {
		return err
	}
	authSvc := auth.New(auth.Options{
		Store: authStore, OTPRequired: cfg.AuthOTPRequired, SecretKey: cfg.AuthSecretKey, CookieSecure: cfg.AuthCookieSecure,
		DevMode:    cfg.AuthDevMode, // config.Load 가 mock 소스에서만 허용한다
		TrustProxy: true,            // compose 에서 backend 포트는 바깥에 없다 — nginx 가 넘기는 X-Real-IP 로 IP 실패 횟수를 센다
	})
	if cfg.AuthDevMode {
		slog.Warn("AUTH_DEV_MODE=true: 개발 전용 로그인 — 실제 서버에서 쓰지 말 것 (초기 관리자 아이디=비밀번호 허용 · 비밀번호 변경 · 라이선스 단계 건너뜀)")
	}
	// 계정이 하나도 없을 때만 ADMIN_USER / ADMIN_INITIAL_PASSWORD 로 관리자 1명 (비밀번호가 비었거나 5자 미만이면 시작 오류)
	if created, err := authSvc.SeedAdmin(ctx, cfg.AdminUser, cfg.AdminInitialPassword); err != nil {
		return fmt.Errorf("initial admin: %w", err)
	} else if created && cfg.AuthDevMode {
		slog.Info("initial admin created (AUTH_DEV_MODE: no password change on first login)", "user", cfg.AdminUser)
	} else if created {
		slog.Info("initial admin created; password change required on first login", "user", cfg.AdminUser)
	}
	go purgeSessions(ctx, authSvc, 10*time.Minute)

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
	var dnsTraced func() bool    // trace_dns 가 지금 돌고 있는지 (/api/info dnsResolve)
	var discovery func() string  // 실제로 쓰이는 컨테이너 발견 방식 (/api/info discovery, mock 은 nil)
	var demoSim demo.Simulator   // mock 소스의 시연 재생(10/30). 가젯 소스는 nil → Docker 로 컨테이너를 띄운다
	var labeler pipeline.Labeler // 감시 · 격리 범위 라벨(11/06) — mock 은 흉내, 가젯은 Docker inspect
	switch cfg.EventSource {
	case "mock":
		m := ingestion.NewMock()
		source, enf, onInstallStart, dnsTraced = m, m, m.SimulateInstall, m.DNSTraced
		demoSim, labeler = m, m
	default:
		g := &ingestion.Gadget{Kinds: cfg.Gadgets, ContainerName: cfg.ContainerName, Discovery: cfg.ContainerDiscovery, DockerHost: cfg.DockerHost, ResolveDNS: cfg.ResolveDNS}
		source, dnsTraced, discovery = g, g.DNSTraced, g.ActiveDiscovery
		lifecycle = &ingestion.DockerLifecycle{DockerHost: cfg.DockerHost}
		de, err := enforcer.NewDocker(cfg.DockerHost)
		if err != nil {
			return err
		}
		// kill 직전 증거(로그 · 파일 변경 · 프로세스)를 모은다. 훅은 700ms 를 넘기면 기다리지 않고 kill 한다(10/20)
		if dc, err := dockerapi.New(cfg.DockerHost); err != nil {
			slog.Warn("evidence disabled: docker", "err", err)
		} else {
			de.BeforeKill = evidence.New(dc, evStore).BeforeKill
			labeler = dc
		}
		enf = de
	}

	// 외부 알림(10/20): 채널이 없으면 no-op
	ntf := notify.New(notify.Config{WebhookURL: cfg.NotifyWebhookURL, SlackURL: cfg.NotifySlackURL, PublicURL: cfg.PublicURL}, slog.Default())
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ntf.Close(c)
	}()

	hub := ws.NewHub(cfg.AllowedOrigins)

	// 판정 미리보기(10/20)가 「같은 이미지로 실행 중인 컨테이너 수」를 센다. mock 소스는 Docker 를 부르지 않는다(수 모름)
	var containers review.ContainerLister
	if cfg.EventSource == "gadget" {
		if dc, err := dockerapi.New(cfg.DockerHost); err == nil {
			containers = dc
		}
	}
	// 종합 판정(11/04): 설치 세션 보고 뒤 같은 패키지의 정적 검사를 서버가 시작한다(SCAN_AUTO). 훅은 곧바로 돌아오고 뒤에서 검사 · 세션 기록을 한다.
	// 검사기(scans)는 review 를 Blocker 로 쓰므로 아래에서 만든다 — 훅은 부를 때 scans · rv 를 읽는다(HTTP 를 받기 전에 둘 다 정해진다)
	var scans *scan.Service
	var rv *review.Service
	installHook := onInstallStart
	if cfg.ScanAuto {
		auto := scan.AutoScan(func() *scan.Service { return scans }, func(ctx context.Context, id, scanID, skip string) error {
			return rv.AttachScan(ctx, id, scanID, skip)
		})
		installHook = func(x model.InstallSession) {
			if onInstallStart != nil {
				onInstallStart(x) // mock 소스의 설치 흉내
			}
			auto(x)
		}
	}
	// 설치 세션 · 건 · 제안 · 차단 목록 · 변경 이력. 엔진에는 저장된 정책 + 차단 도메인 시스템 규칙(blocklist-hosts)
	rv = review.New(review.Options{
		Store: reviewStore, Policies: policies, Audit: audit, Engine: engine, Hub: hub,
		Actor: cfg.ActorName, ActorFrom: api.RequesterName, EnforceKill: cfg.EnforceKill, OnInstallStart: installHook, Notifier: ntf,
		Containers: containers,
	})
	if err := rv.Load(ctx); err != nil {
		return fmt.Errorf("review load: %w", err)
	}
	if err := rv.Reload(ctx); err != nil {
		return fmt.Errorf("review reload: %w", err)
	}
	go rv.Run(ctx)
	// 시연 실행(10/30): DEMO_ENABLED=true 일 때만 — 가젯 소스는 Docker 로 sg-install-demo-* 컨테이너를, mock 은 모의 재생
	var demoSvc *demo.Service
	if cfg.DemoEnabled {
		o := demo.Options{Review: rv, Image: cfg.DemoImage}
		if demoSim != nil {
			o.Simulator = demoSim
		} else {
			dc, err := dockerapi.New(cfg.DockerHost)
			if err != nil {
				return fmt.Errorf("demo: docker: %w", err)
			}
			o.Docker = dc
		}
		demoSvc = demo.New(o)
		slog.Warn("DEMO_ENABLED=true: POST /api/demo/run can start sg-install-demo-* containers — demo only, keep it off in production")
	}
	agg := stats.New()
	// 종합(10/16): 1분 단위 수집량을 10초마다 저장소에 더한다. 끝날 때 한 번 더
	go flushCollected(ctx, agg, collected)
	// 공급망 검사(10/16): Docker 로 검사기 컨테이너를 띄운다. 결과는 정책 · 감사와 같은 저장소(PG 면 scans 테이블)
	var scanStore scan.Store = mem
	if pgScans, ok := reviewStore.(scan.Store); ok {
		scanStore = pgScans
	}
	if dc, err := dockerapi.New(cfg.DockerHost); err != nil {
		slog.Warn("scan disabled: docker", "err", err)
	} else {
		scans = scan.New(scan.Options{Docker: dc, Dir: cfg.ScanDir, Volume: cfg.ScanVolume, GuardDogImage: cfg.GuardDogImage, OSVImage: cfg.OSVImage, Store: scanStore, Blocker: rv,
			Concurrency: cfg.ScanConcurrency, Queue: cfg.ScanQueue, MemoryMB: cfg.ScanMemoryMB, CPUs: cfg.ScanCPUs})
		slog.Info("scan", "auto", cfg.ScanAuto, "concurrency", cfg.ScanConcurrency, "queue", cfg.ScanQueue, "memoryMB", cfg.ScanMemoryMB, "cpus", cfg.ScanCPUs)
		if err := scans.Load(ctx); err != nil {
			slog.Warn("scan load", "err", err)
		}
	}
	pipe := pipeline.New(pipeline.Options{
		EnforceKill:      cfg.EnforceKill,
		IgnoreContainers: cfg.IgnoreContainers,
		WatchContainers:  cfg.WatchContainers,
		Labels:           labeler,
		Enforce:          &pipeline.EnforceScope{Names: cfg.EnforceContainers},
		NormalEventRate:  cfg.NormalEventRate,
		DNSGrace:         cfg.DNSGrace,
	}, engine, enf, hub, agg, audit, buffer)
	pipe.SetReview(rv)
	pipe.SetNotifier(ntf)

	// 연동(11/06): 환경 점검 · 감시 중 컨테이너(파이프라인과 같은 판정) · 연결 테스트(시험 컨테이너 sg-probe-*)
	intOpt := integration.Options{Scoper: pipe, Recorder: rv, Source: cfg.EventSource, EnforceKill: cfg.EnforceKill,
		EnforceNames: cfg.EnforceContainers, HostRoot: os.Getenv("HOST_ROOT")}
	if m, ok := source.(*ingestion.Mock); ok {
		intOpt.Lister, intOpt.Prober = mockContainers{m}, m
	} else if dc, err := dockerapi.New(cfg.DockerHost); err == nil {
		d := integration.Docker{API: dc}
		intOpt.Lister, intOpt.Prober = d, d
	}
	intSvc := integration.New(intOpt)
	pipe.SetObserver(intSvc.Observe)

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

	// AI 도우미(10/20 · 11/09): 읽기 전용 조회 → 한국어 사실 문장 → Claude(기본) · Ollama(예비). 판정 상태 · 링크는 서버가 붙인다
	sum := summary.New(audit, collected, reviewView{rv})
	var chatSvc *chat.Service
	if cfg.AnthropicKey != "" || cfg.OllamaURL != "" {
		o := chat.Options{Provider: cfg.ChatProvider, AnthropicKey: cfg.AnthropicKey, ClaudeModel: cfg.ClaudeModel, ClaudeEffort: cfg.ClaudeEffort,
			OllamaURL: cfg.OllamaURL, Model: cfg.OllamaModel, KeepAlive: cfg.OllamaKeepAlive,
			Review: reviewView{rv}, Audit: audit, Summary: sum, Policies: policies}
		if scans != nil {
			o.Scans = scans // typed nil 을 인터페이스에 넣지 않는다
		}
		if chatSvc, err = chat.New(o); err != nil {
			return fmt.Errorf("chat: %w", err)
		}
		e := chatSvc.Engine() // 키는 남기지 않는다
		slog.Info("chat", "provider", e.Provider, "model", e.Model, "backup", e.Backup)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/events", hub.HandleWS)
	mux.Handle("/", api.Router(api.Deps{
		Engine: engine, Policies: policies, Audit: audit, Buffer: buffer,
		Stats: snapshot, Checks: checks,
		AdminToken:           cfg.AdminToken,
		SandboxToken:         cfg.SandboxToken,
		SGInstallFile:        cfg.SGInstallFile,
		AllowAnonymousWrites: cfg.EventSource == "mock", // 비어 있는 토큰만 익명 허용 (정한 토큰은 mock 이어도 검사)
		Review:               rv,
		Summary:              sum,
		Chat:                 chatSvc,
		Scans:                scans,
		OSV:                  osv.New(),
		AllowedOrigins:       cfg.AllowedOrigins,
		DNSTraced:            dnsTraced,
		Discovery:            discovery,
		Notifier:             ntf,
		Evidence:             evStore,
		PolicyFile:           cfg.PolicyFile,
		EvalReportsDir:       cfg.EvalReportsDir,
		Auth:                 authSvc,
		Demo:                 demoSvc,
		Integration:          intSvc,
		Info: api.Info{Source: cfg.EventSource, Gadgets: cfg.Gadgets, EnforceKill: cfg.EnforceKill,
			GadgetVersion: ingestion.GadgetVersion, WatchContainers: cfg.WatchContainers, IgnoreContainers: cfg.IgnoreContainers},
	}))

	srv := &http.Server{
		Addr: ":" + cfg.Port,
		// /health · 로그인 단계 · sg-install 보고(SANDBOX_TOKEN)를 뺀 전부(/ws/events 포함)를 로그인 뒤로
		Handler:           api.Secure(mux, api.SecureOptions{Auth: authSvc, AdminToken: cfg.AdminToken, AllowedOrigins: cfg.AllowedOrigins}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		// 시연 컨테이너를 먼저 멈추고 지운다(11/02) — srv.Shutdown 뒤에는 run 이 돌아가 저장소가 닫힌다.
		// compose stop 의 기본 유예 10초 안에 끝나도록 8초
		if demoSvc != nil {
			dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
			if err := demoSvc.Shutdown(dctx); err != nil {
				slog.Warn("demo: shutdown did not finish", "err", err)
			}
			dcancel()
		}
		ictx, icancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := intSvc.Shutdown(ictx); err != nil {
			slog.Warn("integration: shutdown did not finish", "err", err)
		}
		icancel()
		hub.Close()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	slog.Info("listening", "addr", srv.Addr, "source", cfg.EventSource,
		"gadgets", cfg.Gadgets, "enforceKill", cfg.EnforceKill, "ignore", strings.Join(cfg.IgnoreContainers, ","), "watch", strings.Join(cfg.WatchContainers, ","),
		"enforceNames", strings.Join(cfg.EnforceContainers, ","), "labels", pipeline.LabelWatch+" · "+pipeline.LabelEnforce)
	// 11/06: 격리는 라벨(supplyguard.enforce) · sandbox · 시연 · ENFORCE_CONTAINERS 이름만 — 전체 감시여도 그 밖은 보류(경고)
	if cfg.EventSource == "gadget" && cfg.EnforceKill && labeler == nil {
		slog.Warn("container labels unavailable: only ENFORCE_CONTAINERS names can be killed", "enforceNames", strings.Join(cfg.EnforceContainers, ","))
	}
	if cfg.AdminToken == "" && cfg.EventSource != "mock" {
		slog.Warn("ADMIN_TOKEN not set; CLI/automation Bearer access is disabled (dashboard login still works)")
	}
	if !cfg.AuthOTPRequired && cfg.EventSource != "mock" {
		slog.Warn("AUTH_OTP_REQUIRED=false on the gadget source; login works without OTP (development only)")
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

// purgeSessions: 유휴 · 절대 만료가 지난 세션을 주기적으로 지운다 (만료 판정 자체는 요청마다 Service.Session 이 한다)
func purgeSessions(ctx context.Context, svc *auth.Service, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := svc.Purge(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Warn("session purge", "err", err)
			}
		}
	}
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

// mockContainers: mock 소스의 흉내 컨테이너를 연동 목록으로
type mockContainers struct{ m *ingestion.Mock }

func (a mockContainers) Containers(context.Context) ([]integration.Container, error) {
	var out []integration.Container
	for _, c := range a.m.Containers() {
		out = append(out, integration.Container{ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels})
	}
	return out, nil
}
