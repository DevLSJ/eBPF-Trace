package dockerapi

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ErrNotFound: Docker 가 404(그런 컨테이너 없음)로 답했다. 오류 문장은 예전 그대로(errors.Is 로만 가린다)
var ErrNotFound = errors.New("docker: no such container")

type notFound struct{ error }

func (notFound) Is(target error) bool { return target == ErrNotFound }
func (e notFound) Unwrap() error      { return e.error }

// Port: 컨테이너 포트 하나. 호스트에 열지 않은 포트는 HostIP · HostPort 가 비어 있다
type Port struct {
	Port     string `json:"port"` // "8080/tcp"
	HostIP   string `json:"hostIp,omitempty"`
	HostPort string `json:"hostPort,omitempty"`
}

// Detail: 감시 중 컨테이너 상세 시트(11/10) — 읽기 전용 inspect 의 일부.
// 환경 변수(Config.Env) · 명령 · 마운트는 비밀이 담길 수 있어 받는 구조에 두지도 않는다(디코딩 단계에서 버린다)
type Detail struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	ImageID      string            `json:"imageId,omitempty"`
	State        string            `json:"state"` // running · created · exited · paused · restarting · removing · dead
	StartedAt    *time.Time        `json:"startedAt,omitempty"`
	RestartCount int               `json:"restartCount"`
	Ports        []Port            `json:"ports"`
	Labels       map[string]string `json:"labels"`
}

// InspectDetail: GET /containers/{id}/json 에서 상세 시트 값만. 없는 컨테이너는 ErrNotFound
func (c *Client) InspectDetail(ctx context.Context, id string) (Detail, error) {
	var raw struct {
		ID           string `json:"Id"`
		Name         string `json:"Name"`
		Image        string `json:"Image"`
		RestartCount int    `json:"RestartCount"`
		State        struct {
			Status    string `json:"Status"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", &raw); err != nil {
		return Detail{}, err
	}
	d := Detail{ID: raw.ID, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Config.Image, ImageID: raw.Image,
		State: raw.State.Status, RestartCount: raw.RestartCount, Ports: []Port{}, Labels: orEmpty(raw.Config.Labels)}
	// 시작한 적 없으면 Docker 는 0001-01-01 을 준다 — 시각 없음
	if t, err := time.Parse(time.RFC3339Nano, raw.State.StartedAt); err == nil && t.Year() > 1 {
		t = t.UTC()
		d.StartedAt = &t
	}
	keys := make([]string, 0, len(raw.NetworkSettings.Ports))
	for k := range raw.NetworkSettings.Ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		binds := raw.NetworkSettings.Ports[k]
		if len(binds) == 0 {
			d.Ports = append(d.Ports, Port{Port: k})
			continue
		}
		for _, b := range binds {
			d.Ports = append(d.Ports, Port{Port: k, HostIP: b.HostIP, HostPort: b.HostPort})
		}
	}
	return d, nil
}
