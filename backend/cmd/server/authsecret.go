package main

import (
	"fmt"
	"unicode/utf8"
)

// minAuthSecret: AUTH_SECRET_KEY 최소 글자 수 (openssl rand -hex 32 = 64자)
const minAuthSecret = 32

// validateAuthSecret: 실제 가젯 소스(운영)는 OTP 비밀값 암호화 키가 32자 이상이어야 시작한다. mock(로컬 개발)은 선택.
// config.Load 에 두지 않는다 — 기본 소스가 gadget 이라 키 없이 Load 를 부르는 기존 설정 테스트가 모두 깨진다.
// 오류 문구에 키 값은 넣지 않는다(길이만).
func validateAuthSecret(source, key string) error {
	if source != "gadget" {
		return nil
	}
	if n := utf8.RuneCountInString(key); n < minAuthSecret {
		return fmt.Errorf("AUTH_SECRET_KEY: EVENT_SOURCE=gadget 이면 %d자 이상 필요(지금 %d자) — 생성: openssl rand -hex 32", minAuthSecret, n)
	}
	return nil
}
