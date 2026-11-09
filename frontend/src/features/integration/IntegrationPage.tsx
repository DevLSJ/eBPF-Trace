import { FlowHero } from '../../components/FlowHero';
import { FLOW } from './model';
import { IntFrame, Skeleton } from './parts';
import { ScenarioWizard } from './ScenarioWizard';
import { useIntegration } from './useIntegration';
import './integration.css';

// 「연동」 페이지(11/06 사용자 결정 · 11/09 밤 3페이지로 나눔): 내 컨테이너를 라벨 한 줄로 SupplyGuard 에 붙이는 절차만.
//   위 = 흐름 그림(자동 재생) · 아래 = 시나리오 고르기 → 입력 → 적용(자동 감지) → 확인
//   환경 점검(수집 준비 상태 + 연결 테스트)은 /integration/env, 감시 중 컨테이너 목록은 /integration/watch
//   문구 규칙(11/06): 요점 위주 개조식 명사형 종결
export function IntegrationPage() {
  const { data, error } = useIntegration();
  return (
    <IntFrame page="setup" screen="integration" ready={!!data} error={error}>
      <section className="int-hero sg-card" data-part="int-hero">
        <div className="int-hero-head">
          <h2 className="int-hero-title">라벨 한 줄로 내 컨테이너 연동</h2>
          <ul className="int-key" data-part="int-key">
            <li>감시 = 라벨 supplyguard.watch=true</li>
            <li>격리 = 라벨 supplyguard.enforce=true 추가 시에만</li>
            <li>서버 재시작 · 설정 변경 없음</li>
          </ul>
        </div>
        <FlowHero nodes={FLOW} part="int-flow" />
      </section>
      {data ? (
        <ScenarioWizard env={data.env} containers={data.containers} />
      ) : (
        <section className="int-wizard sg-card">
          <Skeleton rows={8} />
        </section>
      )}
    </IntFrame>
  );
}
