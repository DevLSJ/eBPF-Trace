package sginstall_test

import (
	"strings"
	"testing"
)

// npm 은 실행할 때마다 자기 사용자 설정 /root/.npmrc 를 연다 — 이것이 sandbox-secrets(kill)에 걸려
// 정상 npm 설치가 격리됐다(11/03 sg-vm 실측: lodash@4.17.21, comm libuv-worker).
// sg-install 은 npm 컨테이너에 NPM_CONFIG_USERCONFIG=/dev/null 을 준다 — 그러면 .npmrc 를 여는 것은
// 설치 스크립트뿐이라 규칙은 그대로 탐지한다(같은 실측: 기본 위반 1 → 이 설정 위반 0).
func TestNpmInstallIgnoresUserNpmrc(t *testing.T) {
	h := newHarness(t)
	h.run(t, sandboxToken, "0", "npm", "lodash@4.17.21")
	run := dockerRunLine(t, h.dockerCalls())
	if !strings.Contains(run, "-e NPM_CONFIG_USERCONFIG=/dev/null") {
		t.Fatalf("npm sandbox must not read the user npmrc, docker run was:\n%s", run)
	}
}

// pip · cargo 컨테이너에는 npm 설정을 넣지 않는다(바뀌는 것은 npm 뿐)
func TestPipInstallHasNoNpmConfig(t *testing.T) {
	h := newHarness(t)
	h.run(t, sandboxToken, "0", "pip", "requests")
	if run := dockerRunLine(t, h.dockerCalls()); strings.Contains(run, "NPM_CONFIG") {
		t.Fatalf("pip sandbox must not get npm settings, docker run was:\n%s", run)
	}
}

func dockerRunLine(t *testing.T, calls string) string {
	t.Helper()
	for _, l := range strings.Split(calls, "\n") {
		if strings.HasPrefix(l, "run ") {
			return l
		}
	}
	t.Fatalf("no docker run call:\n%s", calls)
	return ""
}
