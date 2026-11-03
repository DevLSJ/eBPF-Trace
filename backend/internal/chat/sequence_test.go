package chat

import (
	"context"
	"strings"
	"testing"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

type seqPolicies struct{}

func (seqPolicies) ListPolicies(context.Context) ([]rules.Rule, error) {
	return []rules.Rule{{ID: "chain-download-secrets", Kind: model.KindSequence, Action: model.ActionKill, DryRun: true, WindowSeconds: 10,
		Steps: []rules.Rule{{Kind: model.KindExec, DenyComms: []string{"wget"}}, {Kind: model.KindOpen, DenyPaths: []string{"/root/.netrc"}}}}}, nil
}

// 연쇄 규칙(11/04): 정책 사실 문장에 kind 이름이 빠지지 않는다 — 「연쇄(sequence) 규칙」
func TestPolicySentenceSequenceKind(t *testing.T) {
	s := newTestService(t, newFakeOllama(t), func(o *Options) { o.Policies = seqPolicies{} })
	f, _, err := s.RunTool(context.Background(), ToolPolicy, map[string]string{"id": "chain-download-secrets"})
	if err != nil {
		t.Fatal(err)
	}
	if all := joined(f); !strings.Contains(all, "연쇄(sequence) 규칙") {
		t.Errorf("policy 문장에 「연쇄(sequence) 규칙」 없음:\n%s", all)
	}
}
