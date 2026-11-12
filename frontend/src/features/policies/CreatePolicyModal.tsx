import { useState, type ReactNode } from 'react';
import { Modal } from '../../components/Modal';
import { PolicyEditor } from '../../components/PolicyEditor';
import { useUnsaved } from '../../hooks/useUnsaved';
import { fromTemplate, KIND_TEXT, TEMPLATES, type ListField } from '../../lib/policyEasy';
import type { Rule } from '../../lib/types';
import { ContainersCard } from './ContainersCard';

// 정책 생성 큰 2단 창(11/09 — 사용자 결정 「정책 생성 버튼」 · 「우측에 적용 도커」 → 「적용 컨테이너」):
//   왼쪽 = 정책 입력(템플릿에서 시작 → 쉬운 설정 · 고급 폼 · 고급 YAML · 저장 전 확인), 오른쪽 = 적용 컨테이너 카드.
//   바닥 줄 = 취소 · 저장 전 확인. 바꾼 값이 있으면 닫을 때 「계속 편집 / 버리고 닫기」(공통 Modal xl · hooks/useUnsaved)
//   start 가 있으면(이벤트 「이 행동 막기」 · 새 기본 규칙 · 주소의 템플릿) 템플릿 고르기를 건너뛴다
export interface CreateStart {
  rule: Rule;
  fresh: { field: ListField; value: string } | null;
  intro?: ReactNode;
  autoCheck?: boolean;
}

export function CreatePolicyModal({
  start,
  canWrite,
  enforceKill,
  existingIds,
  onClose,
  onSaved,
}: {
  start: CreateStart | null;
  canWrite: boolean;
  enforceKill: boolean;
  existingIds: string[];
  onClose: () => void;
  onSaved: (r: Rule) => void;
}) {
  const [picked, setPicked] = useState<CreateStart | null>(null);
  const [side, setSide] = useState<HTMLElement | null>(null);
  const [foot, setFoot] = useState<HTMLElement | null>(null);
  const [value, setValue] = useState<unknown>(null);
  const unsaved = useUnsaved(value, value !== null);
  const begin = start ?? picked;
  return (
    <Modal
      size="xl"
      kind="policy-create"
      title="정책 생성"
      guard={() => unsaved.dirty}
      onClose={onClose}
      side={begin ? <div ref={setSide} className="h-full" /> : undefined}
      foot={(close) => (
        <>
          <div ref={setFoot} className="contents" />
          <button type="button" data-action="form-cancel" onClick={close} className="sg-btn sg-btn-secondary order-1 ml-auto">
            취소
          </button>
        </>
      )}
    >
      {begin ? (
        <div data-testid="editor" className="flex h-full min-h-[min(60vh,560px)] flex-col">
          <PolicyEditor
            rule={begin.rule}
            isNew
            autoCheck={begin.autoCheck}
            canWrite={canWrite}
            enforceKill={enforceKill}
            existingIds={existingIds}
            fresh={begin.fresh}
            intro={begin.intro}
            containers={{ render: (p) => <ContainersCard {...p} />, host: side }}
            footHost={foot}
            onValue={setValue}
            onSaved={onSaved}
            onDeleted={onClose}
          />
        </div>
      ) : (
        <Templates
          onPick={(key) => {
            const t = TEMPLATES.find((x) => x.key === key);
            setPicked({ rule: fromTemplate(key, existingIds), fresh: null, intro: t ? `템플릿 「${t.title}」에서 시작합니다. 저장 전에 모두 고칠 수 있습니다.` : undefined });
          }}
        />
      )}
    </Modal>
  );
}

// 목적별 템플릿에서 시작(10/16)
function Templates({ onPick }: { onPick: (key: string) => void }) {
  return (
    <div className="py-2" data-view="templates">
      <p className="text-sm text-text-2">무엇을 막을지 고르면 값이 채워진 채로 시작합니다.</p>
      <div className="mt-3 grid grid-cols-[repeat(auto-fill,minmax(14rem,1fr))] gap-3">
        {TEMPLATES.map((t) => (
          <button
            key={t.key}
            type="button"
            data-template={t.key}
            onClick={() => onPick(t.key)}
            className={`grid gap-1 rounded-[var(--r-md)] border p-3.5 text-left hover:border-accent hover:bg-accent-soft ${t.key === 'blank' ? 'border-dashed border-border-strong' : 'border-border'}`}
          >
            <span className="justify-self-start rounded-[var(--r-sm)] bg-surface-2 px-1.5 py-0.5 text-xs text-text-2">{KIND_TEXT[t.rule.kind][0]}</span>
            <b className="text-sm font-semibold text-text">{t.title}</b>
            <small className="text-xs text-text-3">{t.desc}</small>
          </button>
        ))}
      </div>
    </div>
  );
}
