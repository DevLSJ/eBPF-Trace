import { createContext, useContext, type ReactNode } from 'react';
import type { Catalog, CommandKind, DemoSession, Envelope } from './api';

export const steps = ['프로젝트 준비', '부품과 보안 검사', '위험과 배포 차단', '수정과 재검사', '검증된 버전 배포', '운영 관측과 결과'];
export const instructions = [
  ['체험할 온라인 주문 서비스를 확인합니다.', '같은 프로젝트로 검사부터 운영까지 연결해서 이해할 수 있습니다.', '“이 프로젝트로 시작”을 누르세요.'],
  ['서비스가 사용하는 외부 소프트웨어 부품을 확인합니다.', '직접 작성하지 않은 코드도 우리 서비스의 일부이기 때문입니다.', '“보안 검사 시작”을 누르고 검사 결과를 확인하세요.'],
  ['세 가지 문제와 배포가 막히는 이유를 살펴봅니다.', '문제의 근거를 알아야 필요한 수정만 선택할 수 있습니다.', '“현재 버전 배포해 보기”로 정책의 차단을 체험하세요.'],
  ['부품과 빌드 과정의 수정 전·후를 비교합니다.', '파일을 바꾸는 것과 검증하는 것은 서로 다른 과정입니다.', '수정을 적용한 다음 “다시 검사”를 누르세요.'],
  ['검사한 버전과 배포할 파일이 같은지 확인합니다.', '검사 후 파일이 바뀌었다면 기존 통과 결과를 믿을 수 없습니다.', '“검증된 버전 시연 배포”를 누르세요.'],
  ['배포된 버전과 관측한 이벤트를 연결합니다.', '배포 전 확인만으로 운영 중의 모든 위험을 알 수는 없습니다.', '“운영 이벤트 체험”을 누른 뒤 결과를 확인하세요.'],
];
export const move = (hash: string) => { location.hash = hash; };
export const go = (step: number) => move(`#supply/demo/${step}`);
export const when = (value: string) => new Date(value).toLocaleString('ko-KR', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
export type Topic = 'guide' | 'risk' | 'evidence' | 'component' | 'changes' | 'deployment';
export type DemoContextValue = {
  session: DemoSession | null; catalog: Catalog | null; busy: string;
  act: (kind: CommandKind, args?: Record<string, unknown>, then?: (value: Envelope) => void) => Promise<void>;
  help: (title: string, content: ReactNode, topic?: Topic) => void;
  prepare: () => void; resume: () => void; report: () => void; reset: () => void;
};
export const DemoContext = createContext<DemoContextValue | null>(null);
export function useDemo() { const value = useContext(DemoContext); if (!value) throw new Error('Demo provider required'); return value; }
