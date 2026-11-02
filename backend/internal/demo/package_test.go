package demo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 임베드한 데모 패키지 사본은 정본 deploy/demo/reqeusts 와 바이트가 같아야 한다(10/30).
// 정본 경로가 없거나 아직 dns-exfil 이 없는 옛 정본이면 건너뛴다 — 머지 때 메인이 정본을 사본에 복사해 맞춘다.
func TestDemoPackageMirrorsDeploy(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "deploy", "demo", "reqeusts")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("정본 없음: %v", err)
	}
	canon, err := os.ReadFile(filepath.Join(dir, "setup.py"))
	if err != nil {
		t.Skipf("정본 setup.py 없음: %v", err)
	}
	if !strings.Contains(string(canon), "dns-exfil") {
		t.Skip("deploy/demo/reqeusts 정본에 아직 dns-exfil 이 없음(10/30 이전) — 머지 때 메인이 맞춘다")
	}
	for _, name := range PackageFiles {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("정본 %s: %v", name, err)
		}
		got, err := pkgFS.ReadFile("reqeusts/" + name)
		if err != nil {
			t.Fatalf("사본 %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: 사본이 정본과 다름 (사본 %d바이트 · 정본 %d바이트)", name, len(got), len(want))
		}
	}
}

// 사본 자체의 모양: 시나리오 순서(dns-exfil 은 domain 다음 · udp 앞)와 TXT 질의 함수가 들어 있다
func TestDemoPackageShape(t *testing.T) {
	b, err := pkgFS.ReadFile("reqeusts/setup.py")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`("domain", scn_domain),`, `("dns-exfil", scn_dns_exfil),`, `("udp", scn_udp),`, "def scn_dns_exfil():", `b"\x04data\x05exfil\x07example\x00\x00\x10\x00\x01"`, "all|shell|revshell|direct-ip|domain|dns-exfil|udp"} {
		if !strings.Contains(s, want) {
			t.Errorf("setup.py 에 %q 가 없음", want)
		}
	}
	if strings.Index(s, `("dns-exfil", scn_dns_exfil),`) < strings.Index(s, `("domain", scn_domain),`) || strings.Index(s, `("dns-exfil", scn_dns_exfil),`) > strings.Index(s, `("udp", scn_udp),`) {
		t.Error("dns-exfil 은 domain 다음 · udp 앞이어야 한다")
	}
	if strings.Contains(s, "현재 엔진은 TCP 만 관찰") || !strings.Contains(s, "엔진은 TCP 와 DNS(53 · 5353)만 관찰") {
		t.Error("udp 주석이 10/30 문구가 아님")
	}
	readme, _ := pkgFS.ReadFile("reqeusts/README.md")
	if !strings.Contains(string(readme), "`dns-exfil`") {
		t.Error("README 시나리오 표에 dns-exfil 이 없음")
	}
	// PUT archive 용 tar: pkg/reqeusts/<file> 경로
	tarb, err := Archive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(tarb, []byte("pkg/reqeusts/setup.py")) || !bytes.Contains(tarb, []byte("pkg/reqeusts/README.md")) {
		t.Fatal("archive must carry pkg/reqeusts/{setup.py,README.md}")
	}
}
