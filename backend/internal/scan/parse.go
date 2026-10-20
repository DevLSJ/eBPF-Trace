package scan

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

// GuardDog 3.x JSON: results{규칙: [] | {} | [{location "파일:줄", code, match, message}]}, risk_score{score, label}
type gdOut struct {
	Results   map[string]json.RawMessage `json:"results"`
	RiskScore *struct {
		Score float64 `json:"score"`
		Label string  `json:"label"`
	} `json:"risk_score"`
}

func parseGuardDog(b []byte, root string) ([]model.ScanFinding, *model.ScanRisk, error) {
	var o gdOut
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, nil, fmt.Errorf("GuardDog 결과를 읽을 수 없습니다: %w", err)
	}
	var out []model.ScanFinding
	for rule, raw := range o.Results {
		var items []struct {
			Location string `json:"location"`
			Match    string `json:"match"`
			Message  string `json:"message"`
		}
		if json.Unmarshal(raw, &items) != nil {
			continue // {} 또는 메타데이터 규칙의 문자열
		}
		cat := "capability"
		if strings.HasPrefix(rule, "threat-") {
			cat = "threat"
		}
		for _, it := range items {
			file, line := it.Location, 0
			if i := strings.LastIndexByte(it.Location, ':'); i > 0 {
				file = it.Location[:i]
				line, _ = strconv.Atoi(it.Location[i+1:])
			}
			file = strings.TrimPrefix(strings.TrimPrefix(file, root), "/")
			out = append(out, model.ScanFinding{Rule: rule, Category: cat, Message: it.Message, File: file, Line: line, Match: it.Match})
		}
	}
	slices.SortFunc(out, func(a, b model.ScanFinding) int {
		if a.Category != b.Category {
			return strings.Compare(b.Category, a.Category) // threat 먼저
		}
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		return a.Line - b.Line
	})
	var risk *model.ScanRisk
	if o.RiskScore != nil {
		risk = &model.ScanRisk{Score: o.RiskScore.Score, Label: o.RiskScore.Label}
	}
	return out, risk, nil
}

// OSV-Scanner 2.x JSON: results[].packages[]{package{name, version, ecosystem}, vulnerabilities[], groups[{ids, max_severity}]}
func parseOSV(b []byte, direct map[string]bool) ([]model.ScanVuln, error) {
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var o struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID string `json:"id"`
				} `json:"vulnerabilities"`
				Groups []struct {
					MaxSeverity string `json:"max_severity"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("OSV-Scanner 결과를 읽을 수 없습니다: %w", err)
	}
	var out []model.ScanVuln
	for _, r := range o.Results {
		for _, p := range r.Packages {
			if len(p.Vulnerabilities) == 0 {
				continue
			}
			v := model.ScanVuln{Package: p.Package.Name, Version: p.Package.Version, Ecosystem: p.Package.Ecosystem, Count: len(p.Vulnerabilities),
				Direct: direct == nil || direct[strings.ToLower(p.Package.Name)]}
			var maxSev float64
			for _, g := range p.Groups {
				if f, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil && f > maxSev {
					maxSev, v.MaxSeverity = f, g.MaxSeverity
				}
			}
			for _, x := range p.Vulnerabilities[:min(5, len(p.Vulnerabilities))] {
				v.IDs = append(v.IDs, x.ID)
			}
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b model.ScanVuln) int {
		fa, _ := strconv.ParseFloat(a.MaxSeverity, 64)
		fb, _ := strconv.ParseFloat(b.MaxSeverity, 64)
		switch {
		case fa > fb:
			return -1
		case fa < fb:
			return 1
		}
		return b.Count - a.Count
	})
	return out, nil
}

// directNames: requirements*.txt 에 적힌 이름(직접 의존성). 그 밖의 잠금 파일이면 nil(모두 직접으로 본다)
func directNames(fileName string, content []byte) map[string]bool {
	if !strings.HasSuffix(strings.ToLower(fileName), ".txt") {
		return nil
	}
	m := map[string]bool{}
	for _, ln := range strings.Split(string(content), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "-") {
			continue
		}
		end := strings.IndexAny(ln, "=<>!~[; ")
		if end < 0 {
			end = len(ln)
		}
		m[strings.ToLower(strings.ReplaceAll(ln[:end], "_", "-"))] = true
	}
	return m
}
