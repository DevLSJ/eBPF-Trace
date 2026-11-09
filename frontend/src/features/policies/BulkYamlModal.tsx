import { useEffect, useState } from 'react';
import { ActionButton } from '../../components/ActionButton';
import { CodeWindow, CW_BODY } from '../../components/CodeWindow';
import { ConfirmDialog, Modal } from '../../components/Modal';
import { useToast } from '../../hooks/toast-context';
import { useUnsaved } from '../../hooks/useUnsaved';
import { api, errorText } from '../../lib/api';

// 「YAML 일괄 적용」(옛 정책 화면 「전체 YAML」 — 기능 그대로 큰 창으로): GET /api/policies/export 를 고쳐 PUT /api/policies 로 전체 교체.
// 시스템 규칙(blocklist-hosts)은 내보내지 않고 그대로 둔다. 조회자는 읽기만
// 불러오는 동안 입력 칸 · 적용 단추는 aria-disabled + 사유(11/09 G16 — 초점은 감)
const LOAD_FIRST = 'YAML 을 불러온 뒤 쓸 수 있습니다';
export function BulkYamlModal({ canWrite, ruleCount, onClose, onApplied }: { canWrite: boolean; ruleCount: number; onClose: () => void; onApplied: () => void }) {
  const toast = useToast();
  const [text, setText] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [ask, setAsk] = useState(false);
  const unsaved = useUnsaved(text, text !== null);

  useEffect(() => {
    api
      .exportYaml()
      .then(setText)
      .catch((e: unknown) => setLoadErr(errorText(e)));
  }, []);

  const apply = async () => {
    if (text === null) return;
    setBusy(true);
    try {
      const rs = await api.applyYaml(text);
      unsaved.reset();
      onApplied();
      toast(`정책 ${rs.length}개를 적용했습니다.`, { key: 'policy-yaml', tone: 'ok' });
      setMsg({ ok: true, text: `정책 ${rs.length}개를 엔진에 적용했습니다.` });
    } catch (e) {
      setMsg({ ok: false, text: `적용하지 못했습니다(${errorText(e)}).` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      size="xl"
      kind="bulk-yaml"
      title="YAML 일괄 적용"
      guard={() => unsaved.dirty}
      busy={busy}
      onClose={onClose}
      foot={(close) => (
        <>
          {msg && (
            <span role={msg.ok ? 'status' : 'alert'} className={`min-w-0 flex-1 truncate text-sm ${msg.ok ? 'text-ok-text' : 'text-danger-text'}`} title={msg.text}>
              {msg.text}
            </span>
          )}
          {!canWrite && <span className="mr-auto text-xs text-text-3">읽기 전용입니다. 전체 교체는 관리자만 합니다</span>}
          <button type="button" onClick={close} className="sg-btn sg-btn-secondary">
            닫기
          </button>
          {canWrite && (
            <ActionButton
              onClick={() => setAsk(true)}
              reason={text === null ? LOAD_FIRST : busy ? '적용 중입니다' : null}
              className="sg-btn sg-btn-primary"
            >
              {busy ? '적용 중…' : '전체 교체 후 적용'}
            </ActionButton>
          )}
        </>
      )}
    >
      <div className="flex h-[min(62vh,640px)] min-h-72 flex-col gap-2 py-1">
        <p className="text-xs text-text-3">지금 정책 전체를 YAML 로 고쳐 한 번에 교체합니다. 시스템 규칙 blocklist-hosts 는 들어 있지 않고 그대로 남습니다.</p>
        {loadErr ? (
          <p role="alert" className="text-sm text-danger-text">
            YAML 을 불러오지 못했습니다({loadErr}).
          </p>
        ) : (
          <div className="min-h-0 flex-1">
            {/* 11/04f 코드 창(R1 11/04) — policies.yaml · 입력칸이 곧 코드 영역 */}
            <CodeWindow name="policies.yaml" body="raw" fill>
              <textarea
                className={CW_BODY}
                wrap="off"
                value={text ?? '불러오는 중…'}
                aria-disabled={text === null ? 'true' : undefined}
                title={text === null ? LOAD_FIRST : undefined}
                spellCheck={false}
                onChange={(e) => setText(e.target.value)}
                readOnly={!canWrite || text === null}
                aria-label="전체 정책 YAML"
              />
            </CodeWindow>
          </div>
        )}
      </div>
      {ask && (
        <ConfirmDialog
          title="정책 전체를 YAML 로 교체할까요?"
          body="YAML 의 내용으로 지금 정책을 모두 바꾸고 엔진에 바로 적용합니다."
          impact={[`지금 정책 ${ruleCount}개가 YAML 의 내용으로 바뀝니다.`, 'YAML 에 없는 정책은 지워집니다.', '변경 이력에 「정책 일괄 적용」으로 남습니다.']}
          requireCheck="YAML 에 없는 정책이 지워짐을 확인했습니다"
          confirmLabel="교체"
          danger
          onCancel={() => setAsk(false)}
          onConfirm={() => {
            setAsk(false);
            void apply();
          }}
        />
      )}
    </Modal>
  );
}
