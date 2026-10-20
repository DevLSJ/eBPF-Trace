package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/scan"
)

// 공급망 검사(10/16): GET 목록 · 상세는 토큰 없이, 검사 시작 · 차단 목록에 올리기는 ADMIN(서버 자원 · 정책 변경)
func (h *handlers) routeScans(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/scans", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, h.Scans.List()) })
	mux.HandleFunc("GET /api/scans/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := h.Scans.Get(r.PathValue("id")); ok {
			writeJSON(w, http.StatusOK, s)
			return
		}
		writeErr(w, http.StatusNotFound, "검사 없음")
	})
	mux.HandleFunc("POST /api/scans", h.auth(h.startScan))
	mux.HandleFunc("POST /api/scans/{id}/block", h.auth(func(w http.ResponseWriter, r *http.Request) {
		pid, err := h.Scans.Block(r.Context(), r.PathValue("id"))
		if err != nil {
			scanErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"proposalId": pid})
	}))
}

// startScan: JSON {kind, manager, name, version, url} 또는 multipart(kind=file, file=…) — 파일은 50MB
func (h *handlers) startScan(w http.ResponseWriter, r *http.Request) {
	var in scan.Input
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, 51<<20)
		mr, err := r.MultipartReader()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "multipart 형식 오류")
			return
		}
		in.Kind = "file"
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					writeErr(w, http.StatusRequestEntityTooLarge, "파일은 50MB 까지 올릴 수 있습니다")
					return
				}
				writeErr(w, http.StatusBadRequest, "업로드 오류: "+err.Error())
				return
			}
			if part.FormName() == "file" {
				in.FileName, in.File = part.FileName(), part
				id, err := h.Scans.Start(r.Context(), in) // 파일 부분을 다 읽어 작업 볼륨에 둔다
				if err != nil {
					scanErr(w, err)
					return
				}
				writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "파일을 고르세요")
		return
	}
	var body struct{ Kind, Manager, Name, Version, URL string }
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 형식 오류: "+err.Error())
		return
	}
	id, err := h.Scans.Start(r.Context(), scan.Input{Kind: body.Kind, Manager: body.Manager, Name: body.Name, Version: body.Version, URL: body.URL})
	if err != nil {
		scanErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func scanErr(w http.ResponseWriter, err error) {
	var se *scan.Error
	if errors.As(err, &se) {
		writeErr(w, se.Status, se.Msg)
		return
	}
	reviewErr(w, "scan", err)
}
