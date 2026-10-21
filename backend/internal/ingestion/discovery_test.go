package ingestion

import (
	"errors"
	"testing"
)

// pickDiscovery(10/20): auto 는 fanotify 컬렉션을 먼저 만들고, 생성 단계에서 실패하면 docker-events 로 내려간다.
// 명시한 값(fanotify | docker-events)은 내려가지 않는다.
func TestPickDiscovery(t *testing.T) {
	errFan := errors.New("fanotify_mark: invalid argument")
	type calls struct{ fan, de, warn int }
	run := func(mode string, fanErr, deErr error) (string, string, error, calls) {
		var c calls
		fan := func() (string, error) { c.fan++; return "fan-collection", fanErr }
		de := func() (string, error) { c.de++; return "de-collection", deErr }
		got, active, err := pickDiscovery(mode, fan, de, func(error) { c.warn++ })
		return got, active, err, c
	}

	cases := []struct {
		name          string
		mode          string
		fanErr, deErr error
		wantGot       string
		wantActive    string
		wantErr       bool
		want          calls
	}{
		{"auto, fanotify ok", "auto", nil, nil, "fan-collection", DiscoveryFanotify, false, calls{1, 0, 0}},
		{"empty = auto", "", nil, nil, "fan-collection", DiscoveryFanotify, false, calls{1, 0, 0}},
		{"auto, fanotify fails -> docker-events", "auto", errFan, nil, "de-collection", DiscoveryDockerEvents, false, calls{1, 1, 1}},
		{"auto, both fail", "auto", errFan, errors.New("no socket"), "", "", true, calls{1, 1, 1}},
		{"fanotify explicit fails -> no fallback", "fanotify", errFan, nil, "", "", true, calls{1, 0, 0}},
		{"fanotify explicit ok", "fanotify", nil, nil, "fan-collection", DiscoveryFanotify, false, calls{1, 0, 0}},
		{"docker-events explicit", "docker-events", nil, nil, "de-collection", DiscoveryDockerEvents, false, calls{0, 1, 0}},
		{"unknown mode", "runc", nil, nil, "", "", true, calls{0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, active, err, c := run(tc.mode, tc.fanErr, tc.deErr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && (got != tc.wantGot || active != tc.wantActive) {
				t.Fatalf("got %q/%q, want %q/%q", got, active, tc.wantGot, tc.wantActive)
			}
			if c != tc.want {
				t.Fatalf("calls %+v, want %+v", c, tc.want)
			}
		})
	}
}

// auto 가 docker-events 까지 실패하면 두 원인을 모두 담아 돌려준다 (fanotify 원인을 잃지 않는다)
func TestPickDiscoveryBothFailKeepsCauses(t *testing.T) {
	errFan, errDE := errors.New("fan-cause"), errors.New("de-cause")
	_, _, err := pickDiscovery("auto",
		func() (int, error) { return 0, errFan },
		func() (int, error) { return 0, errDE },
		func(error) {})
	if !errors.Is(err, errFan) || !errors.Is(err, errDE) {
		t.Fatalf("both causes must be wrapped: %v", err)
	}
}

// Run 전(또는 비리눅스)에는 선택된 방식이 없다
func TestGadgetActiveDiscoveryBeforeRun(t *testing.T) {
	g := &Gadget{Discovery: "auto"}
	if got := g.ActiveDiscovery(); got != "" {
		t.Fatalf("before Run: want empty, got %q", got)
	}
}
