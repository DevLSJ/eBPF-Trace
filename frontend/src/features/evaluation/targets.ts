// 정적 목표치(11/09 저녁 사용자 답 「정적 줄에 목표치」 — 값은 질문 예시값). 판정 4칸 줄 칩 · 칩 툴팁 · 칸 머리 「상태 (?)」 설명이 이 한 곳을 쓴다.
// 둘 다 맞으면(경계 포함) 통과, 하나라도 못 미치면 주의
export const STATIC_TARGET = { detectionRate: 0.8, falsePositiveRate: 0.02 } as const;

const p0 = (x: number) => `${Math.round(x * 100)}%`;
export const STATIC_TARGET_TEXT = `탐지율 ${p0(STATIC_TARGET.detectionRate)} 이상 · 오판율 ${p0(STATIC_TARGET.falsePositiveRate)} 이하`;

export const meetsStaticTarget = (detectionRate: number, falsePositiveRate: number) => detectionRate >= STATIC_TARGET.detectionRate && falsePositiveRate <= STATIC_TARGET.falsePositiveRate;
