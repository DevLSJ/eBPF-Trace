package chat

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// 긴 대시 후처리(11/09 사용자 결정 「모든 페이지와 탭의 — 표기 없앰」): 시스템 프롬프트로 금지해도 모델이 쓸 수 있어
// 화면에 나가기 전에 서버가 고친다. 대시 줄기(대시 사이에 공백만 있으면 하나로 본다)를 같은 줄의 앞뒤 글자로 판단한다.
//   - 줄에 대시뿐 → 빈 줄
//   - 줄 맨 앞(들여쓰기 뒤) → 개조식 표시 「- 」
//   - 줄 끝 · 닫는 문장 부호 앞 · 여는 괄호 뒤 → 지움(둘레 공백 포함)
//   - 구분 부호(: , · - 등) 뒤 → 공백 하나(원래 공백이 있을 때만)
//   - 숫자—숫자 → 「~」(범위)
//   - 그 밖 → 「, 」
// 대시가 없는 글은 공백까지 그대로 둔다.

const emDash = '\u2014'

// cleanDashes: 답 전체를 한 번에 고친다(dashStream 에 통째로 흘린 것과 같다)
func cleanDashes(s string) string {
	if !strings.ContainsRune(s, emDash) {
		return s
	}
	var b strings.Builder
	ds := &dashStream{emit: func(tok string) error { b.WriteString(tok); return nil }}
	_ = ds.write(s)
	_ = ds.flush()
	return b.String()
}

// dashStream: 흘려보내는 답 조각을 고쳐 emit 으로 넘긴다. 조각을 어디서 끊어도 이어 붙인 결과는 cleanDashes(전체)와 같다.
// 결정에 뒤 글자가 필요한 부분(줄 끝 공백 · 대시 줄기)만 붙잡아 두고, 나머지는 받은 즉시 넘긴다. 다 받으면 flush 를 부른다.
type dashStream struct {
	emit func(string) error

	partial []byte // 조각 끝에서 잘린 UTF-8 바이트

	midLine bool // 이 줄에 공백 아닌 글자를 이미 넘겼다
	last    rune // 그 마지막 글자(midLine 일 때)

	ws1    strings.Builder // 붙잡은 공백(대시 줄기 앞)
	inRun  bool            // 대시 줄기를 붙잡고 있다
	ws2    strings.Builder // 줄기 뒤 공백
	spaced bool            // 줄기 둘레에 공백이 있었다
}

func (d *dashStream) write(p string) error {
	if p == "" {
		return nil
	}
	data := p
	if len(d.partial) > 0 {
		data = string(d.partial) + p
		d.partial = d.partial[:0]
	}
	var out strings.Builder
	for i := 0; i < len(data); {
		if !utf8.FullRuneInString(data[i:]) {
			d.partial = append(d.partial, data[i:]...)
			break
		}
		r, n := utf8.DecodeRuneInString(data[i:])
		d.feed(&out, r, data[i:i+n])
		i += n
	}
	if out.Len() == 0 {
		return nil
	}
	return d.emit(out.String())
}

// flush: 답 끝 — 붙잡은 것을 줄 끝으로 판단해 넘긴다
func (d *dashStream) flush() error {
	var out strings.Builder
	d.resolveEnd(&out)
	if len(d.partial) > 0 {
		out.Write(d.partial) // 끝까지 잘린 바이트는 손대지 않는다
		d.partial = d.partial[:0]
	}
	if out.Len() == 0 {
		return nil
	}
	return d.emit(out.String())
}

func (d *dashStream) feed(out *strings.Builder, r rune, raw string) {
	switch {
	case r == emDash:
		if d.inRun && d.ws2.Len() > 0 { // 「— —」: 사이 공백까지 한 줄기
			d.spaced = true
			d.ws2.Reset()
		}
		d.inRun = true
	case r == ' ' || r == '\t' || r == '\r':
		if d.inRun {
			d.ws2.WriteString(raw)
			d.spaced = true
		} else {
			d.ws1.WriteString(raw)
		}
	case r == '\n':
		d.resolveEnd(out)
		out.WriteString(raw)
		d.midLine, d.last = false, 0
	default:
		d.resolve(out, r)
		out.WriteString(raw)
		d.midLine, d.last = true, r
	}
}

// resolveEnd: 줄 끝(또는 답 끝)에서 붙잡은 것 — 대시 줄기면 둘레 공백까지 지우고, 공백뿐이면 그대로
func (d *dashStream) resolveEnd(out *strings.Builder) {
	if !d.inRun {
		out.WriteString(d.ws1.String())
	}
	d.reset()
}

// resolve: 다음 글자 next 가 왔을 때 붙잡은 것을 넘긴다
func (d *dashStream) resolve(out *strings.Builder, next rune) {
	if !d.inRun {
		out.WriteString(d.ws1.String())
		d.reset()
		return
	}
	switch {
	case !d.midLine: // 줄 맨 앞: 개조식 표시, 들여쓰기는 그대로
		out.WriteString(d.ws1.String())
		out.WriteString("- ")
	case strings.ContainsRune(closingMarks, next) || strings.ContainsRune(openingMarks, d.last):
		// 지움
	case strings.ContainsRune(separatorMarks, d.last):
		if d.spaced || d.ws1.Len() > 0 {
			out.WriteByte(' ')
		}
	case unicode.IsDigit(d.last) && unicode.IsDigit(next):
		out.WriteByte('~')
	default:
		out.WriteString(", ")
	}
	d.reset()
}

func (d *dashStream) reset() {
	d.ws1.Reset()
	d.ws2.Reset()
	d.inRun, d.spaced = false, false
}

const (
	closingMarks   = ".,!?;:)]}>」』”’）…。、"
	openingMarks   = "([{<「『“‘（"
	separatorMarks = ":,;·→/-.!?…、"
)
