package model

import "time"

// Role: 계정 역할. admin 은 모든 쓰기, viewer 는 읽기(GET)만
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

func (r Role) Valid() bool { return r == RoleAdmin || r == RoleViewer }

// User: 로그인 계정. 비밀값(PwHash · OTPSecret · RecoveryHashes)은 JSON 으로 내보내지 않는다.
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	DisplayName  string `json:"displayName"`
	Role         Role   `json:"role"`
	PwHash       string `json:"-"`
	MustChangePW bool   `json:"mustChangePassword"`
	// OTPSecret: base32 비밀값. AUTH_SECRET_KEY 가 있으면 "v1:" 접두어의 AES-GCM 암호문
	OTPSecret   string `json:"-"`
	OTPEnabled  bool   `json:"otpEnabled"`
	OTPLastStep int64  `json:"-"`
	// RecoveryHashes: 남은 복구 코드의 SHA-256(사용자 id 로 소금) — 쓰면 지운다
	RecoveryHashes []string   `json:"-"`
	FailedCount    int        `json:"-"`
	LockedUntil    time.Time  `json:"-"`
	Disabled       bool       `json:"disabled"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastLoginAt    *time.Time `json:"lastLoginAt"`
}

// SessionState: 로그인 단계. need_password → need_license → need_otp_enroll | need_otp → active
type SessionState string

const (
	StateNeedPassword  SessionState = "need_password"
	StateNeedLicense   SessionState = "need_license"
	StateNeedOTPEnroll SessionState = "need_otp_enroll"
	StateNeedOTP       SessionState = "need_otp"
	StateActive        SessionState = "active"
)

// Session: DB 에는 토큰의 SHA-256(hex)만 둔다.
type Session struct {
	Hash      string
	UserID    string
	State     SessionState
	CreatedAt time.Time
	LastSeen  time.Time
	IP        string
	UA        string
	// OTPPending: OTP 등록 중 이 세션에 발급한 비밀값(확인 전) — 같은 세션에서 다시 부르면 같은 값
	OTPPending string
	// OTPFailures: 이 세션의 OTP 실패 수 (많으면 세션을 끊는다)
	OTPFailures int
}

// License: 서버당 한 행. 키 원문은 저장하지 않는다(가린 값만).
type License struct {
	KeyMasked    string    `json:"keyMasked"`
	Kind         string    `json:"kind"` // trial
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	RegisteredBy string    `json:"registeredBy"`
}

// AuthAudit: 인증 사건 기록 (로그인 · 비밀번호 · 라이선스 · OTP · 계정 변경 · 로그아웃)
type AuthAudit struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	IP     string    `json:"ip"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail"`
}
