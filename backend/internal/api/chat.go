package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/chat"
)

// ChatPattern: 라우트 등록 · auth.Middleware ViewerWrites(읽기 전용 POST)에 쓰는 패턴
const ChatPattern = "POST /api/chat"

// chatPing: 모델을 기다리는 동안 보내는 SSE 주석 간격 — nginx proxy_read_timeout(기본 60초) · 브라우저가 끊지 않게.
// 첫 답은 모델 로드로 100초 넘게 걸린다(실측)
var chatPing = 15 * time.Second

// ChatHandler: POST /api/chat {question, page, history:[{role,text}]} → text/event-stream.
//
//	event: token  data: "조각"(JSON 문자열)
//	event: facts  data: {intent, tool, status, sentences, cases, scan}
//	event: links  data: [{label, href}]
//	event: done   data: {}
//	event: error  data: "문구"(JSON 문자열)
//
// 스트림은 done 또는 error 하나로 끝난다. 시작 전 오류는 JSON: 400(빈 질문 · 500자 초과 · JSON 아님) · 429(생성 중).
// 읽기 전용이라 조회자도 부를 수 있다(ViewerWrites 에 ChatPattern).
func ChatHandler(svc *chat.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req chat.Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "본문은 {question, page, history} JSON 이어야 함")
			return
		}
		run, err := svc.Start(req)
		switch {
		case errors.Is(err, chat.ErrBusy):
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		case err != nil:
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		rc := http.NewResponseController(w)
		h := w.Header()
		h.Set("Content-Type", "text/event-stream; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Accel-Buffering", "no") // nginx 가 조각을 모아 두지 않게
		w.WriteHeader(http.StatusOK)

		var mu sync.Mutex
		write := func(b []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if _, err := w.Write(b); err != nil {
				return err
			}
			return rc.Flush()
		}
		_ = write([]byte(": start\n\n"))

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(chatPing)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if write([]byte(": ping\n\n")) != nil {
						return
					}
				}
			}
		}()
		defer func() { close(stop); wg.Wait() }() // 핸들러가 끝난 뒤 w 에 쓰지 않게

		run.Stream(r.Context(), func(event string, data any) error {
			b, err := json.Marshal(data)
			if err != nil {
				return err
			}
			buf := make([]byte, 0, len(event)+len(b)+16)
			buf = append(buf, "event: "...)
			buf = append(buf, event...)
			buf = append(buf, "\ndata: "...)
			buf = append(buf, b...)
			buf = append(buf, "\n\n"...)
			return write(buf)
		})
	}
}
