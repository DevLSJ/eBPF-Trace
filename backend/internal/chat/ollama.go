package chat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// errModelDown: 모델에 닿지 못함 — Ollama 꺼짐 · 주소 틀림 · 모델 없음(404), Claude 키 · 한도 · 서버 오류(claudeErr). 화면에는 MsgModelDown
var errModelDown = errors.New("model unavailable")

// ollama: POST {base}/api/chat 클라이언트(Ollama 의 NDJSON 스트리밍 · 도구 호출)
type ollama struct {
	base, model, keepAlive string
	hc                     *http.Client
}

type oMsg struct {
	Role      string      `json:"role"`
	Content   string      `json:"content"`
	ToolCalls []oToolCall `json:"tool_calls,omitempty"`
}

type oToolCall struct {
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

type oReq struct {
	Model     string  `json:"model"`
	Messages  []oMsg  `json:"messages"`
	Stream    bool    `json:"stream"`
	Tools     []oTool `json:"tools,omitempty"`
	KeepAlive string  `json:"keep_alive,omitempty"`
}

type oResp struct {
	Message oMsg   `json:"message"`
	Done    bool   `json:"done"`
	Error   string `json:"error"`
}

func (c *ollama) post(ctx context.Context, r oReq) (*http.Response, error) {
	r.Model, r.KeepAlive = c.model, c.keepAlive
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", errModelDown, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, fmt.Errorf("%w: status %d %s", errModelDown, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// pick: 도구 고르기 — stream:false 한 번. 모델이 도구를 부르면 Message.ToolCalls 가 찬다
func (c *ollama) pick(ctx context.Context, msgs []oMsg, tools []oTool) (oMsg, error) {
	resp, err := c.post(ctx, oReq{Messages: msgs, Stream: false, Tools: tools})
	if err != nil {
		return oMsg{}, err
	}
	defer resp.Body.Close()
	var out oResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		if ctx.Err() != nil {
			return oMsg{}, ctx.Err()
		}
		return oMsg{}, fmt.Errorf("ollama pick decode: %w", err)
	}
	if out.Error != "" {
		return oMsg{}, fmt.Errorf("ollama: %s", out.Error)
	}
	return out.Message, nil
}

// stream: 답 생성 — NDJSON 한 줄마다 조각을 onToken 으로. done:true 가 오기 전에 끊기면 오류
func (c *ollama) stream(ctx context.Context, msgs []oMsg, onToken func(string) error) error {
	resp, err := c.post(ctx, oReq{Messages: msgs, Stream: true})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r oResp
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("ollama stream decode: %w", err)
		}
		if r.Error != "" {
			return fmt.Errorf("ollama: %s", r.Error)
		}
		if r.Message.Content != "" {
			if err := onToken(r.Message.Content); err != nil {
				return err
			}
		}
		if r.Done {
			return nil
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("ollama stream: %w", err)
	}
	return io.ErrUnexpectedEOF
}

// --- 도구 정의(모델 도구 호출용 JSON 스키마) ---

type oTool struct {
	Type     string    `json:"type"`
	Function oToolFunc `json:"function"`
}

type oToolFunc struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

func tool(name, desc string, props map[string]any, required ...string) oTool {
	if props == nil {
		props = map[string]any{}
	}
	p := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		p["required"] = required
	}
	return oTool{Type: "function", Function: oToolFunc{Name: name, Description: desc, Parameters: p}}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var toolDefs = []oTool{
	tool(ToolPending, "판정 대기 중인 건(격리 · 경고된 설치 검사 · 런타임 컨테이너)을 요약한다", nil),
	tool(ToolAudit, "감사 로그에서 컨테이너 이름 또는 정책 id 로 위반 기록을 찾는다(왜 격리 · 경고됐는지)", map[string]any{
		"container": str("컨테이너 이름(일부도 됨)"), "rule": str("정책 id"),
	}),
	tool(ToolSummary, "기간 동안의 eBPF 수집량 · 위반 수 · 가장 많이 걸린 정책 · 설치 검사 결과를 요약한다", map[string]any{
		"range": map[string]any{"type": "string", "enum": []string{"1h", "24h", "7d"}, "description": "기간"},
	}),
	tool(ToolLatestScan, "가장 최근 공급망 검사(GuardDog · OSV-Scanner) 결과", nil),
	tool(ToolScan, "공급망 검사 한 건의 결과", map[string]any{"id": str("검사 id(scan-0001 꼴)")}, "id"),
	tool(ToolBlocklist, "차단 목록(패키지 · 이미지 · 도메인)", nil),
	tool(ToolPolicy, "정책 하나가 무엇을 막는지 설명한다", map[string]any{"id": str("정책 id")}, "id"),
}
