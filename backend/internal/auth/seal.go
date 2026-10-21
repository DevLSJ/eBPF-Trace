package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// sealer: OTP 비밀값 저장 형식. AUTH_SECRET_KEY 가 없으면 평문 그대로(위험 — 보고서 참조),
// 있으면 "v1:" + base64(nonce ‖ AES-256-GCM 암호문). 키는 SHA-256(AUTH_SECRET_KEY).
// AAD 에 사용자 id 를 넣어 다른 계정 행으로 옮긴 암호문은 열리지 않는다.
type sealer struct{ aead cipher.AEAD }

const sealPrefix = "v1:"

func newSealer(key string) sealer {
	if key == "" {
		return sealer{}
	}
	k := sha256.Sum256([]byte(key))
	block, _ := aes.NewCipher(k[:]) // 32바이트 키라 오류 없음
	aead, _ := cipher.NewGCM(block)
	return sealer{aead: aead}
}

func (s sealer) seal(userID, plain string) (string, error) {
	if s.aead == nil {
		return plain, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nonce, nonce, []byte(plain), []byte("otp:"+userID))
	return sealPrefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

func (s sealer) open(userID, stored string) (string, error) {
	rest, enc := strings.CutPrefix(stored, sealPrefix)
	if !enc {
		return stored, nil // 키를 넣기 전에 저장한 평문
	}
	if s.aead == nil {
		return "", errors.New("OTP 비밀값이 암호화되어 있는데 AUTH_SECRET_KEY 가 없음")
	}
	b, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil || len(b) < s.aead.NonceSize() {
		return "", errors.New("OTP 비밀값 형식 오류")
	}
	n := s.aead.NonceSize()
	pt, err := s.aead.Open(nil, b[:n], b[n:], []byte("otp:"+userID))
	if err != nil {
		return "", errors.New("OTP 비밀값을 열 수 없음(키가 다름)")
	}
	return string(pt), nil
}
