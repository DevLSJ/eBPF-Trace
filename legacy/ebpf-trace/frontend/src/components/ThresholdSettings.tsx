import { useEffect, useState } from 'react';
import { errorMessage, getThresholds, saveThresholds } from '../api/client';
import type { Thresholds } from '../types';

const fields: { key: keyof Thresholds; label: string; min: number; max?: number; step: number; hint: string }[] = [
  { key: 'syn_pps_threshold', label: 'SYN Flood 기준 (SYN/s)', min: 1, step: 1, hint: '출발지 전체 SYN 패킷 수' },
  { key: 'syn_ratio_threshold', label: 'SYN 비율', min: 0, max: 1, step: 0.01, hint: 'SYN Flood 판정에 함께 적용' },
  { key: 'port_cnt_threshold', label: 'Port Scan 목적지 포트 수', min: 2, max: 65536, step: 1, hint: '10초 내 출발지별 고유 포트 수' },
  { key: 'baseline_pps', label: '기준 트래픽 (pps)', min: 1, step: 1, hint: '트래픽 급증 판정의 기준값' },
  { key: 'spike_threshold_multiplier', label: '트래픽 급증 배수', min: 1.01, step: 0.01, hint: '기준 트래픽 × 배수 이상 탐지' },
  { key: 'large_flow_threshold', label: '대용량 플로우 (bytes/s)', min: 1, step: 1, hint: '12,500,000 bytes/s = 100 Mbps' },
  { key: 'anomaly_threshold', label: 'ML 이상 점수 임계값', min: -1, max: -0.001, step: 0.001, hint: '기본 −0.1 · 변경 시 기존 성능 검증 범위 밖' },
];

export function ThresholdSettings({ onSaved }: { onSaved: (value: Thresholds) => void }) {
  const canEdit = window.isSecureContext;
  const [value, setValue] = useState<Thresholds | null>(null), [token, setToken] = useState('');
  const [error, setError] = useState(''), [success, setSuccess] = useState(false), [saving, setSaving] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    getThresholds().then(data => { if (active) { setValue(data); setError(''); } }).catch(e => { if (active) setError(errorMessage(e)); });
    return () => { active = false; };
  }, [retry]);
  return <section className="panel settings-panel" id="settings">
    <div className="panel-heading"><div><h2>탐지 설정</h2><p>조회는 누구나, 변경은 관리자 토큰으로 인증합니다.</p></div></div>
    {error && <div className="error-banner" role="alert">{error}{!value && <button onClick={() => setRetry(v => v + 1)}>다시 시도</button>}</div>}
    {!value ? <p className="panel-message">설정을 불러오는 중입니다.</p> : <form onSubmit={async e => {
      e.preventDefault(); setSaving(true); setError(''); setSuccess(false);
      try { const updated = await saveThresholds(value, token); setValue(updated); setToken(''); setSuccess(true); onSaved(updated); }
      catch (err) { setError(errorMessage(err)); } finally { setSaving(false); }
    }}>
      {!canEdit && <p className="health-banner">관리자 토큰 보호를 위해 변경은 HTTPS 또는 localhost SSH 터널에서 가능합니다. 현재 값은 조회할 수 있습니다.</p>}
      <fieldset disabled={saving || !canEdit}><div className="settings-grid">{fields.map(field => <label key={field.key}>{field.label}<input type="number" required min={field.min} max={field.max} step={field.step} value={Number.isNaN(value[field.key]) ? '' : value[field.key]} onChange={e => { setSuccess(false); setValue({ ...value, [field.key]: e.target.value === '' ? NaN : Number(e.target.value) }); }}/><small>{field.hint}</small></label>)}</div>
      <div className="settings-actions"><label>관리자 토큰<input type="password" required autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="저장 시에만 사용"/></label><button className="primary-button" type="submit" disabled={!token || !Object.values(value).every(Number.isFinite)}>{saving ? '저장 중…' : '임계값 저장'}</button></div></fieldset>
      {success && <p className="save-success" role="status">탐지 임계값을 저장했습니다.</p>}
    </form>}
  </section>;
}
