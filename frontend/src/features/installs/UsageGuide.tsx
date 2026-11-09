import { useState } from 'react';
import { ActionButton } from '../../components/ActionButton';
import { CodeWindow } from '../../components/CodeWindow';
import { Modal } from '../../components/Modal';
import { useToast } from '../../hooks/toast-context';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';

// 설치 검사 「사용 방법」(11/06 결정 B · 11/09) — ① 내려받기 ② 환경 변수 ③ 실행 · 결과.
// 토큰(SANDBOX_TOKEN)은 관리자에게만 오고, 화면에는 가린 채 보인다(녹화 · 발표 화면에 남지 않게). 복사는 실제 값

const EXIT_CODES: [string, string][] = [
  ['0', '통과 — 위반 없음'],
  ['2', '위반 — 격리 또는 경고, 이 화면에 새 건'],
  ['3', '차단 목록 — 컨테이너를 띄우기 전 거부'],
  ['1', '설치 실패 — 패키지 이름 · 버전 확인'],
  ['4', '결과 확인 불가 — 통과로 보지 않음'],
  ['69', '백엔드 연결 실패 — SUPPLYGUARD_API 확인'],
  ['77', '토큰 거부 — SUPPLYGUARD_SANDBOX_TOKEN 확인'],
];
const TOKEN_PLACEHOLDER = '<관리자에게 받은 SANDBOX_TOKEN>';
const RUN = ['./sg-install pip requests', './sg-install npm lodash@4', './sg-install cargo ripgrep'].join('\n');

const mask = (t: string) => `${t.slice(0, 4)}••••`;

export function UsageGuide({ onClose }: { onClose: () => void }) {
  const setup = useLoad(api.sginstallSetup);
  const toast = useToast();
  const [show, setShow] = useState(false);
  const s = setup.data;

  const envLines = (reveal: boolean) => {
    if (!s) return '';
    const lines = [`export SUPPLYGUARD_API=${s.api}`];
    if (s.tokenRequired) lines.push(`export SUPPLYGUARD_SANDBOX_TOKEN=${s.token ? (reveal ? s.token : mask(s.token)) : TOKEN_PLACEHOLDER}`);
    return lines.join('\n');
  };
  // 복사 알림에는 명령을 다시 보이지 않는다(토큰이 화면에 남지 않게)
  const copy = (text: string, what: string) => {
    const ok = () => toast(`${what}을(를) 복사했습니다.`, { key: 'copy', tone: 'ok' });
    const fail = () => toast(`${what}을(를) 복사하지 못했습니다 — 직접 입력하세요.`, { key: 'copy', tone: 'warn' });
    try {
      navigator.clipboard.writeText(text).then(ok, fail);
    } catch {
      fail();
    }
  };

  return (
    <Modal title="sg-install 사용 방법" kind="sginstall-usage" onClose={onClose} wide>
      <div data-part="sginstall-guide" className="grid gap-4 text-sm">
        <ul className="grid gap-0.5 text-xs text-text-2">
          <li>패키지를 개발자 PC 가 아닌 일회용 감시 컨테이너에서 설치함</li>
          <li>위반(외부 스크립트 실행 · 자격 증명 읽기 · 허용 밖 연결)이면 설치 완료 전 격리됨</li>
          <li>SupplyGuard 가 감시받는 서버에서 실행 — eBPF 는 그 서버의 컨테이너만 관찰함</li>
        </ul>
        {setup.error != null && <p className="text-xs text-danger-text">설정을 읽지 못했습니다 — 잠시 뒤 다시 여세요</p>}
        {s && !s.reporting && (
          <p data-part="reporting-off" role="note" className="rounded-md border border-[var(--warn-line)] bg-warn-soft px-3 py-2 text-xs">
            설치 보고 꺼짐 — 서버 .env 에 SANDBOX_TOKEN 을 넣고 백엔드를 다시 시작해야 결과가 이 화면에 남습니다
          </p>
        )}

        <section data-step="download" className="grid gap-1.5">
          <h3 className="font-semibold">① 내려받기</h3>
          {s?.download ? (
            <div className="flex flex-wrap items-center gap-2">
              <a href={s.download} download="sg-install" className="sg-btn sg-btn-sm sg-btn-secondary">
                sg-install 내려받기
              </a>
              <span className="text-xs text-text-2">이 서버와 같은 판 · 받은 뒤 서버로 옮겨 실행 권한 부여</span>
            </div>
          ) : (
            <p className="text-xs text-text-2">서버에 스크립트 없음 — 저장소의 tools/sg-install 사용</p>
          )}
          <CodeWindow lang="sh" name="권한">
            {'chmod +x sg-install'}
          </CodeWindow>
        </section>

        <section data-step="env" className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold">② 환경 변수</h3>
            {s?.token && (
              <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" onClick={() => setShow((v) => !v)}>
                {show ? '토큰 가리기' : '토큰 보기'}
              </button>
            )}
            <ActionButton className="sg-btn sg-btn-sm sg-btn-secondary" reason={!s && '설정을 불러온 뒤 쓸 수 있습니다'} onClick={() => copy(envLines(true), '환경 변수')}>
              환경 변수 복사
            </ActionButton>
          </div>
          <CodeWindow lang="sh" name="환경">
            {envLines(show) || '불러오는 중…'}
          </CodeWindow>
          <p className="text-xs text-text-2">
            {s?.tokenRequired ? (s.token ? '토큰은 설치 보고 전용 — 관리 API 에는 쓸 수 없음' : '토큰은 관리자에게 받기') : '이 서버는 토큰 없이 보고를 받음(mock)'}
          </p>
        </section>

        <section data-step="run" className="grid gap-1.5">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold">③ 실행 · 결과</h3>
            <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" onClick={() => copy('./sg-install pip requests', '실행 명령')}>
              실행 명령 복사
            </button>
          </div>
          <CodeWindow lang="sh" name="실행">
            {RUN}
          </CodeWindow>
          <table data-part="exit-codes" className="sg-table text-xs">
            <thead>
              <tr>
                <th className="w-20">종료 코드</th>
                <th>뜻</th>
              </tr>
            </thead>
            <tbody>
              {EXIT_CODES.map(([code, text]) => (
                <tr key={code}>
                  <td className="num">{code}</td>
                  <td>{text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </Modal>
  );
}
