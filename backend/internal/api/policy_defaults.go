package api

import (
	"encoding/json"
	"net/http"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/rules"
)

// 새 기본 규칙 안내(10/20): 정책은 빈 DB 에 한 번만 시드되므로, 버전이 올라 기본 정책 파일에 생긴 규칙 · 옵션은
// 기존 서버에 저절로 들어가지 않는다. 화면은 이 비교를 보여 주고, 관리자가 미리보기 뒤 골라서 저장한다(POST /api/policies).

type policyDiff struct {
	ID      string     `json:"id"`
	Default rules.Rule `json:"default"`
	Current rules.Rule `json:"current"`
}

type policyDefaults struct {
	// Missing: 기본 정책 파일에는 있는데 지금 정책에 없는 규칙
	Missing []rules.Rule `json:"missing"`
	// Differs: 같은 id 인데 조건 · 행동이 다른 규칙 (설명 · 꺼짐 · dryRun 은 사용자가 바꾸는 값이라 비교하지 않는다)
	Differs []policyDiff `json:"differs"`
}

// policyDefaults: GET /api/policies/defaults — 읽기 전용
func (h *handlers) policyDefaults(w http.ResponseWriter, _ *http.Request) {
	defs, err := rules.LoadFile(h.PolicyFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "기본 정책 파일을 읽을 수 없음: "+err.Error())
		return
	}
	cur := map[string]rules.Rule{}
	for _, r := range h.Engine.Rules() {
		cur[r.ID] = r
	}
	out := policyDefaults{Missing: []rules.Rule{}, Differs: []policyDiff{}}
	for _, d := range defs {
		c, ok := cur[d.ID]
		if !ok {
			out.Missing = append(out.Missing, d)
			continue
		}
		if !sameConditions(d, c) {
			out.Differs = append(out.Differs, policyDiff{ID: d.ID, Default: d, Current: c})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func sameConditions(a, b rules.Rule) bool {
	norm := func(r rules.Rule) string {
		r.Description, r.Disabled, r.DryRun = "", false, false
		j, _ := json.Marshal(r)
		return string(j)
	}
	return norm(a) == norm(b)
}
