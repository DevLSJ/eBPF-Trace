"""Fixed educational fixtures, never represented as live vulnerability intelligence."""

import hashlib
import hmac
import json

POLICY_REVISION = "demo-policy-2026-01"
DEMO_KEY = b"public-educational-hmac-key-not-a-production-signing-key"
BUILDER = "demo-ci/verified-builder"
PROJECT = {
    "name": "온라인 주문 서비스",
    "description": "고객의 주문을 접수하고 결제 상태를 보여주는 작은 웹 서비스입니다.",
    "environment": "격리된 시연 환경",
    "source": "고정 예시 프로젝트 · 실제 저장소와 연결되지 않음",
}
STAGES = ["사용 부품 확인", "알려진 취약점 확인", "빌드 출처와 서명 확인", "배포 정책 확인"]


def artifact(number):
    fixed = number == 2
    return {
        "project": PROJECT["name"],
        "version": f"1.0.{number - 1}",
        "source_revision": "demo-source-fixed-02" if fixed else "demo-source-initial-01",
        "builder": BUILDER if fixed else "developer-laptop/unverified",
        "components": [
            {
                "id": "orders",
                "name": "order-service",
                "version": f"1.0.{number - 1}",
                "purpose": "주문 접수와 결제 상태 API",
                "license": "Private",
                "depends_on": ["parser", "ui", "metrics"],
                "example": True,
            },
            {
                "id": "parser",
                "name": "order-parser",
                "version": "1.4.3" if fixed else "1.4.2",
                "purpose": "주문 입력값 해석",
                "license": "MIT",
                "depends_on": [],
                "example": True,
            },
            {
                "id": "ui",
                "name": "React",
                "version": "19.2.0",
                "purpose": "주문 화면 표시",
                "license": "MIT",
                "depends_on": [],
                "example": False,
            },
            {
                "id": "metrics",
                "name": "usage-metrics" if fixed else "telemetry-helper",
                "version": "2.0.0" if fixed else "0.9.0",
                "purpose": "서비스 사용량 집계",
                "license": "MIT" if fixed else "AGPL-3.0-only",
                "depends_on": [],
                "example": True,
            },
        ],
    }


def file_digest(value):
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def signature(digest):
    return hmac.new(DEMO_KEY, digest.encode(), hashlib.sha256).hexdigest()


def evaluate(version):
    """Run real comparisons on fixture inputs, with provenance for every conclusion."""
    value = version.artifact
    components = value["components"]
    actual_digest = file_digest(value)
    findings = []
    parser = next((c for c in components if c["name"] == "order-parser"), None)
    if parser and parser["version"] == "1.4.2":
        findings.append(
            {
                "id": "DEMO-001",
                "title": "주문 입력을 처리하는 부품에 예시 취약점이 있습니다",
                "component": "order-parser 1.4.2",
                "impact": "온라인 주문 서비스의 주문 접수 API",
                "evidence": "고정 예시 권고 DEMO-001과 부품 이름·버전이 일치합니다. 실제 CVE 조회 결과가 아닙니다.",
                "why": "외부에서 들어온 주문 내용을 제대로 확인하지 않는 상황을 가정합니다. 서비스가 멈추거나 잘못된 주문이 처리될 수 있어 배포 전에 확인합니다.",
                "fix": "시연에서 수정 대상으로 지정한 order-parser 1.4.3으로 변경한 후 다시 검사합니다.",
                "check_id": "vulnerabilities",
                "source": "예시 검사 결과",
            }
        )
    unapproved = [c for c in components if c["license"] not in {"MIT", "Apache-2.0", "Private"}]
    if unapproved:
        findings.append(
            {
                "id": "POLICY-LICENSE",
                "title": "아직 사용 승인을 받지 않은 부품이 있습니다",
                "component": ", ".join(c["name"] for c in unapproved),
                "impact": "온라인 주문 서비스의 사용량 집계 기능",
                "evidence": "시연 프로젝트는 MIT·Apache-2.0·내부 코드만 사전 승인합니다. AGPL-3.0-only는 이 예시 정책에서 검토 대기입니다.",
                "why": "라이선스가 나쁘다는 뜻은 아닙니다. 이 프로젝트에서 지켜야 할 사용 조건을 아직 확인하지 않았다는 뜻입니다. 실제 법률 판단이 아닙니다.",
                "fix": "이번 시연에서는 사전 승인한 usage-metrics 2.0.0(MIT)로 교체합니다. 실제 서비스에서는 호환성 확인과 담당자 검토가 필요합니다.",
                "check_id": "policy",
                "source": "서버의 시연 허용 목록 비교",
            }
        )
    intact = actual_digest == version.digest
    signed = bool(version.signature) and hmac.compare_digest(
        version.signature, signature(actual_digest)
    )
    trusted = value["builder"] == BUILDER
    if not (intact and signed and trusted):
        findings.append(
            {
                "id": "POLICY-BUILD",
                "title": "누가 만든 배포 파일인지 확인할 수 없습니다",
                "component": "order-service 배포 파일",
                "impact": "서비스 전체의 배포 파일",
                "evidence": f"빌드 출처: {value['builder']}. 파일 지문 일치: {intact}. 시연 서명 일치: {signed}.",
                "why": "검사한 코드와 배포할 파일이 다르거나 빌드 과정이 확인되지 않으면, 부품을 고쳤더라도 다른 파일이 배포될 수 있습니다.",
                "fix": "허용된 시연 빌더로 새 파일을 만들고 시연 서명과 파일 고유 지문을 재검사합니다.",
                "check_id": "provenance",
                "source": "서버 SHA-256·교육용 HMAC·빌더 비교",
            }
        )
    checks = [
        {
            "id": "inventory",
            "title": STAGES[0],
            "passed": bool(components),
            "source": "서버에서 예시 배포 파일 읽기",
            "evidence": f"직접 부품과 의존 부품 {len(components)}개를 확인했습니다.",
        },
        {
            "id": "vulnerabilities",
            "title": STAGES[1],
            "passed": not any(f["id"] == "DEMO-001" for f in findings),
            "source": "예시 검사 결과 · 실제 취약점 DB 미연동",
            "evidence": "고정 권고 DEMO-001과 이름·버전을 대조했습니다. 목록에 없는 실제 취약점이 없다는 뜻은 아닙니다.",
        },
        {
            "id": "provenance",
            "title": STAGES[2],
            "passed": bool(intact and signed and trusted),
            "source": "서버의 실제 지문·시연 서명 비교",
            "evidence": "SHA-256 재계산 + 공개된 교육용 HMAC 키 + 허용된 시연 빌더 확인. 운영 서명 검증을 대체하지 않습니다.",
        },
        {
            "id": "policy",
            "title": STAGES[3],
            "passed": not findings,
            "source": f"서버 정책 평가 · {POLICY_REVISION}",
            "evidence": "예시 취약점 없음, 승인된 사용 조건, 신뢰하는 시연 빌드, 검사 파일 일치를 모두 요구합니다.",
        },
    ]
    return checks, findings


REPLAY_FEATURES = {
    "pkt_rate": 4500,
    "byte_rate": 270000,
    "syn_ratio": 1,
    "port_entropy": 0,
    "port_cnt": 1,
    "flow_duration": 1000,
    "avg_pkt_size": 60,
}
