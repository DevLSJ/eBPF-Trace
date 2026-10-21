package ingestion

import (
	"errors"
	"fmt"
)

// 컨테이너 발견 방식 (CONTAINER_DISCOVERY). auto 는 시작할 때 둘 중 하나로 정해진다.
const (
	DiscoveryAuto         = "auto"
	DiscoveryFanotify     = "fanotify"      // IG 기본 runc fanotify 훅 — 컨테이너 첫 동작부터 본다
	DiscoveryDockerEvents = "docker-events" // Docker 이벤트 API — 시작 직후 약 0.1초를 놓칠 수 있다
)

// pickDiscovery: mode 에 맞는 컨테이너 컬렉션을 만들고, 실제로 쓰인 방식을 돌려준다.
// auto(빈 값 포함)는 fanotify 를 먼저 만들고, 생성 단계에서 실패하면 warn 으로 원인을 알린 뒤 docker-events 로 내려간다.
// 명시한 fanotify · docker-events 는 내려가지 않는다(설정한 대로 안 되면 시작하지 않는다).
// 판정은 생성 단계 오류로만 한다 — 가젯이 돈 뒤의 오류로 방식을 바꾸지 않는다.
func pickDiscovery[T any](mode string, fanotify, dockerEvents func() (T, error), warn func(error)) (T, string, error) {
	var zero T
	switch mode {
	case DiscoveryFanotify:
		c, err := fanotify()
		if err != nil {
			return zero, "", fmt.Errorf("container discovery (fanotify): %w", err)
		}
		return c, DiscoveryFanotify, nil
	case DiscoveryDockerEvents:
		c, err := dockerEvents()
		if err != nil {
			return zero, "", fmt.Errorf("container discovery (docker-events): %w", err)
		}
		return c, DiscoveryDockerEvents, nil
	case DiscoveryAuto, "":
		c, fanErr := fanotify()
		if fanErr == nil {
			return c, DiscoveryFanotify, nil
		}
		warn(fanErr)
		c, deErr := dockerEvents()
		if deErr != nil {
			return zero, "", fmt.Errorf("container discovery (auto): %w", errors.Join(
				fmt.Errorf("fanotify: %w", fanErr), fmt.Errorf("docker-events: %w", deErr)))
		}
		return c, DiscoveryDockerEvents, nil
	default:
		return zero, "", fmt.Errorf("container discovery: unknown mode %q (auto | fanotify | docker-events)", mode)
	}
}
