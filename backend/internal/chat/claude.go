package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// Claude(11/09 사용자 결정): Claude 가 기본, Ollama 는 예비. 흐름은 Ollama 때와 같다 — 도구 고르기 1회(stream:false) + 답 스트리밍 1회.
// 밖으로 나가는 것: 질문 · 최근 대화 · 서버가 조회한 사실 문장(건 · 정책 · 컨테이너 이름 · 위반 예시 일부). 증거 원문 · 계정 · 비밀값은 보내지 않는다.

const (
	DefaultClaudeModel  = "claude-opus-5-5"
	DefaultClaudeEffort = "low" // 짧은 한국어 답(3~5문장) — 대화형은 low 로 충분하다
	pickMaxTokens       = 8192  // 생각(Opus 5.5 는 끌 수 없음) + 도구 호출
	answerMaxTokens     = 16000
	fallbackBeta        = "server-side-fallback-2026-07-01"
)

// errRefused: 모델 안전 장치가 답을 거절(stop_reason refusal) — 화면에는 MsgRefused, 조회한 사실은 그대로 보인다
var errRefused = errors.New("claude refused")

type claude struct {
	c         anthropic.Client
	model     string
	effort    anthropic.OutputConfigEffort
	fallbacks bool // 서버 쪽 대체(fallbacks:"default") — 거절된 요청을 Anthropic 이 다른 모델로 다시 돌린다. Haiku 는 대체가 없어 끈다
}

func newClaude(key, model, effort, baseURL string, hc *http.Client) *claude {
	opts := []option.RequestOption{option.WithAPIKey(key), option.WithMaxRetries(2)}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	if hc != nil {
		opts = append(opts, option.WithHTTPClient(hc))
	}
	return &claude{
		c:         anthropic.NewClient(opts...),
		model:     model,
		effort:    anthropic.OutputConfigEffort(effort),
		fallbacks: !strings.HasPrefix(model, "claude-haiku"),
	}
}

func (c *claude) params(msgs []oMsg, maxTokens int64) anthropic.MessageNewParams {
	system, conv := claudeMessages(msgs)
	p := anthropic.MessageNewParams{
		Model:        anthropic.Model(c.model),
		MaxTokens:    maxTokens,
		Messages:     conv,
		OutputConfig: anthropic.OutputConfigParam{Effort: c.effort},
	}
	if system != "" {
		p.System = []anthropic.TextBlockParam{{Text: system}}
	}
	return p
}

func (c *claude) reqOpts() []option.RequestOption {
	if !c.fallbacks {
		return nil
	}
	return []option.RequestOption{option.WithHeaderAdd("anthropic-beta", fallbackBeta), option.WithJSONSet("fallbacks", "default")}
}

// pick: 도구 고르기 — tool_choice 는 auto(Opus 5.5 는 강제 선택이 400). tool_use 는 oToolCall 로 옮겨 기존 validCall 이 검사한다
func (c *claude) pick(ctx context.Context, msgs []oMsg, tools []oTool) (oMsg, error) {
	p := c.params(msgs, pickMaxTokens)
	p.Tools = claudeTools(tools)
	resp, err := c.c.Messages.New(ctx, p, c.reqOpts()...)
	if err != nil {
		return oMsg{}, claudeErr(ctx, err)
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return oMsg{}, errRefused
	}
	out := oMsg{Role: "assistant"}
	for _, b := range resp.Content {
		switch v := b.AsAny().(type) {
		case anthropic.TextBlock:
			out.Content += v.Text
		case anthropic.ToolUseBlock:
			var args map[string]any
			if json.Unmarshal(v.Input, &args) != nil {
				continue // 깨진 인자는 버린다 — validCall 이 다음 후보를 본다
			}
			var tc oToolCall
			tc.Function.Name, tc.Function.Arguments = v.Name, args
			out.ToolCalls = append(out.ToolCalls, tc)
		}
	}
	return out, nil
}

// stream: 답 생성 — 글자 조각(text_delta)만 onToken 으로. 생각 블록은 흘리지 않는다. 마지막 stop_reason 이 refusal 이면 errRefused
func (c *claude) stream(ctx context.Context, msgs []oMsg, onToken func(string) error) error {
	st := c.c.Messages.NewStreaming(ctx, c.params(msgs, answerMaxTokens), c.reqOpts()...)
	defer st.Close()
	refused := false
	for st.Next() {
		switch e := st.Current().AsAny().(type) {
		case anthropic.ContentBlockDeltaEvent:
			if d, ok := e.Delta.AsAny().(anthropic.TextDelta); ok && d.Text != "" {
				if err := onToken(d.Text); err != nil {
					return err
				}
			}
		case anthropic.MessageDeltaEvent:
			refused = e.Delta.StopReason == anthropic.StopReasonRefusal // 서버 쪽 대체가 이어 답하면 마지막 값은 end_turn
		}
	}
	if err := st.Err(); err != nil {
		return claudeErr(ctx, err)
	}
	if refused {
		return errRefused
	}
	return nil
}

// claudeErr: 닿지 못함 · 키 · 한도 · 서버 오류는 errModelDown(예비 Ollama 로 넘길 수 있음). 오류 문구엔 상태 코드만 — 요청 · 응답 원문은 남기지 않는다
func claudeErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ae *anthropic.Error
	if errors.As(err, &ae) {
		switch c := ae.StatusCode; {
		case c == http.StatusUnauthorized, c == http.StatusForbidden, c == http.StatusNotFound,
			c == http.StatusRequestTimeout, c == http.StatusTooManyRequests, c >= 500:
			return fmt.Errorf("%w: claude status %d", errModelDown, c)
		default:
			return fmt.Errorf("claude: status %d", c)
		}
	}
	return fmt.Errorf("%w: claude: %v", errModelDown, err)
}

// claudeMessages: system 은 따로, 대화는 user 로 시작 · 같은 역할이 이어지면 합친다(API 는 user/assistant 를 번갈아 받는다)
func claudeMessages(msgs []oMsg) (string, []anthropic.MessageParam) {
	type turn struct{ role, text string }
	var sys []string
	var ts []turn
	for _, m := range msgs {
		txt := strings.TrimSpace(m.Content)
		switch {
		case m.Role == "system":
			sys = append(sys, m.Content)
		case txt == "" || (m.Role != "user" && m.Role != "assistant"):
		case len(ts) == 0 && m.Role == "assistant":
		case len(ts) > 0 && ts[len(ts)-1].role == m.Role:
			ts[len(ts)-1].text += "\n\n" + txt
		default:
			ts = append(ts, turn{m.Role, txt})
		}
	}
	out := make([]anthropic.MessageParam, 0, len(ts))
	for _, t := range ts {
		if t.role == "user" {
			out = append(out, anthropic.NewUserMessage(anthropic.NewTextBlock(t.text)))
		} else {
			out = append(out, anthropic.NewAssistantMessage(anthropic.NewTextBlock(t.text)))
		}
	}
	return strings.Join(sys, "\n\n"), out
}

func claudeTools(ts []oTool) []anthropic.ToolUnionParam {
	out := make([]anthropic.ToolUnionParam, 0, len(ts))
	for _, t := range ts {
		tp := anthropic.ToolParam{
			Name:        t.Function.Name,
			Description: anthropic.String(t.Function.Description),
			InputSchema: anthropic.ToolInputSchemaParam{Properties: t.Function.Parameters["properties"]},
		}
		if r, ok := t.Function.Parameters["required"].([]string); ok {
			tp.InputSchema.Required = r
		}
		out = append(out, anthropic.ToolUnionParam{OfTool: &tp})
	}
	return out
}

// --- 모델 고르기 · 예비 ---

// llm: 도구 고르기 · 답 스트리밍. ollama · claude · withBackup 이 따른다
type llm interface {
	pick(ctx context.Context, msgs []oMsg, tools []oTool) (oMsg, error)
	stream(ctx context.Context, msgs []oMsg, onToken func(string) error) error
}

// withBackup: 기본 모델이 닿지 않거나 거절하면 예비로 같은 요청을 한 번 더. 답 조각을 이미 보냈으면 넘기지 않는다(답이 섞이지 않게)
type withBackup struct {
	main, backup llm
	log          *slog.Logger
}

func switchable(err error) bool { return errors.Is(err, errModelDown) || errors.Is(err, errRefused) }

func (w withBackup) pick(ctx context.Context, msgs []oMsg, tools []oTool) (oMsg, error) {
	m, err := w.main.pick(ctx, msgs, tools)
	if err == nil || ctx.Err() != nil || !switchable(err) {
		return m, err
	}
	w.log.Warn("chat: claude unavailable, using ollama", "step", "pick", "err", err)
	return w.backup.pick(ctx, msgs, tools)
}

func (w withBackup) stream(ctx context.Context, msgs []oMsg, onToken func(string) error) error {
	sent := false
	err := w.main.stream(ctx, msgs, func(t string) error { sent = true; return onToken(t) })
	if err == nil || sent || ctx.Err() != nil || !switchable(err) {
		return err
	}
	w.log.Warn("chat: claude unavailable, using ollama", "step", "answer", "err", err)
	return w.backup.stream(ctx, msgs, onToken)
}
