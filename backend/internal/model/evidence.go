package model

import "time"

// 증거 보존(10/20) — 컨테이너를 kill 하기 직전에 모은 가벼운 증거.
// 이미지 스냅샷(docker commit)은 하지 않는다 [사용자 결정].

// FileChange: docker diff 한 줄. Kind 는 A(추가) · C(변경) · D(삭제)
type FileChange struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// Proc: docker top 한 줄
type Proc struct {
	PID  int    `json:"pid"`
	User string `json:"user"`
	Cmd  string `json:"cmd"`
}

// EvidenceFile: 격리 직전에 저장한 설치 스크립트 하나(11/10 증거 코드 보기). 글 파일만, Content 는 앞에서 64KB 까지
type EvidenceFile struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Content   string `json:"content"`
}

type Evidence struct {
	ID            string    `json:"id"`
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	Image         string    `json:"image"`
	CollectedAt   time.Time `json:"collectedAt"`
	// Logs: stdout+stderr 마지막 200줄(256KB 상한, 뒤쪽을 남긴다)
	Logs      string       `json:"logs"`
	Changes   []FileChange `json:"changes"`
	Processes []Proc       `json:"processes"`
	// Files: 설치 스크립트 내용(최대 6개). 옛 증거 · 못 읽었으면 비어 있다
	Files []EvidenceFile `json:"files,omitempty"`
	// Partial: 수집 시간 상한(700ms)이나 오류로 일부만 모았음. Error 에 빠진 부분이 적힌다
	Partial    bool   `json:"partial"`
	DurationMs int    `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// Clone: 슬라이스를 복사한 사본 (메모리 저장소가 돌려줄 때)
func (e Evidence) Clone() Evidence {
	c := e
	if e.Changes != nil {
		c.Changes = append([]FileChange(nil), e.Changes...)
	}
	if e.Processes != nil {
		c.Processes = append([]Proc(nil), e.Processes...)
	}
	if e.Files != nil {
		c.Files = append([]EvidenceFile(nil), e.Files...)
	}
	return c
}
