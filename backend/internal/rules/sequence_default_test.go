package rules

import (
	"reflect"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// 기본 연쇄 규칙(11/03): chain-download-secrets — kill · dryRun 시작, 10초, exec curl/wget → 내부망 밖 연결(포트 · 도메인 무관) → 자격 증명 파일
func TestDefaultPolicySequence(t *testing.T) {
	rs, err := LoadFile("../../policies/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var r Rule
	for _, x := range rs {
		if x.ID == "chain-download-secrets" {
			r = x
		}
	}
	if r.Kind != model.KindSequence || r.Action != model.ActionKill || !r.DryRun || r.Disabled || len(r.Containers) != 0 || r.WindowSeconds != 10 || len(r.Steps) != 3 {
		t.Fatalf("chain-download-secrets: %+v", r)
	}
	if last := rs[len(rs)-1]; last.ID != "chain-download-secrets" || rs[len(rs)-2].ID != "sandbox-dns" {
		t.Fatalf("must be the last default rule, after sandbox-dns: last=%s", last.ID)
	}
	ex, cn, op := r.Steps[0], r.Steps[1], r.Steps[2]
	if ex.Kind != model.KindExec || !reflect.DeepEqual(ex.DenyComms, []string{"curl", "wget"}) {
		t.Fatalf("exec step: %+v", ex)
	}
	if cn.Kind != model.KindConnect || !reflect.DeepEqual(cn.AllowCIDRs, privateCIDRs) || len(cn.AllowHosts)+len(cn.AllowPorts)+len(cn.DenyPorts) != 0 || cn.DirectIP != "" {
		t.Fatalf("connect step: %+v", cn)
	}
	wantPaths := []string{"/etc/shadow", "/root/.ssh/", "/home/*/.ssh/*", "/root/.aws/", "/var/run/secrets/", "/run/secrets/",
		"/root/.netrc", "/root/.git-credentials", "/root/.docker/config.json", "/root/.kube/config"}
	if op.Kind != model.KindOpen || !reflect.DeepEqual(op.DenyPaths, wantPaths) {
		t.Fatalf("open step: %+v", op)
	}

	web := func(ev model.Event) model.Event { return in(ev, "c1", "web-api") }
	// 단일 규칙에 없는 자격 증명 경로 → 연쇄가 판정(kill dry-run)
	for _, p := range []string{"/root/.netrc", "/root/.git-credentials", "/root/.docker/config.json", "/root/.kube/config"} {
		e := New(rs)
		e.Observe(web(sx(0, "wget")))
		e.Observe(web(sc(1, "203.0.113.7", 443))) // https 도 단계(포트 무관)
		v := e.Observe(web(so(2, p)))
		if v.RuleID != "chain-download-secrets" || v.Action != model.ActionKill || !v.DryRun || v.Sequence == nil {
			t.Fatalf("%s: %+v", p, v)
		}
	}
	// 도메인을 아는 공인 목적지도 단계, 내부망은 아님
	e := New(rs)
	known := web(sc(1, "151.101.0.223", 443))
	known.DstHost = "files.pythonhosted.org"
	if v := observeAll(t, e, web(sx(0, "curl")), known, web(so(2, "/root/.netrc"))); v.RuleID != "chain-download-secrets" {
		t.Fatalf("resolved public destination: %+v", v)
	}
	e = New(rs)
	if v := observeAll(t, e, web(sx(0, "curl")), web(sc(1, "172.18.0.4", 5432)), web(so(2, "/root/.netrc"))); v.Matched {
		t.Fatalf("internal destination is not a step: %+v", v)
	}
	// 단일 규칙(sensitive-files kill)이 더 강하면 판정은 단일 규칙, 연쇄는 주석
	e = New(rs)
	v := observeAll(t, e, web(sx(0, "wget")), web(sc(1, "203.0.113.7", 80)), web(so(2, "/root/.ssh/id_rsa")))
	if v.RuleID != "sensitive-files" || v.DryRun || v.Sequence == nil || v.Sequence.RuleID != "chain-download-secrets" {
		t.Fatalf("sensitive-files wins: %+v", v)
	}
	// 단일 규칙 판정은 그대로: 다운로더 실행은 여전히 no-shell-download(kill)
	if v := New(rs).Observe(web(sx(0, "wget"))); v.RuleID != "no-shell-download" || v.Sequence != nil {
		t.Fatalf("single rule verdicts unchanged: %+v", v)
	}
	// 연쇄 규칙이 있는 기본 정책에서도 연쇄가 완성되지 않으면 Observe == Evaluate
	obs, ev := New(rs), New(rs)
	for _, x := range []model.Event{web(sx(0, "wget")), web(sc(1, "203.0.113.7", 8081)), web(so(2, "/etc/hosts")), web(dnsAt(3, "pypi.org"))} {
		if got, want := obs.Observe(x), ev.Evaluate(x); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: Observe %+v != Evaluate %+v", x.Kind, got, want)
		}
	}
}
