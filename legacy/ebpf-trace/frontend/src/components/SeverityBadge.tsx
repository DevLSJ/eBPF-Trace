import type { Severity } from '../types';
import { SEVERITY, termTitle } from '../labels';
export function SeverityBadge({ severity }: { severity: Severity }) {
  const term = SEVERITY[severity];
  return <span className={`badge ${severity}`} title={term ? termTitle(term) : undefined}><i/>{term?.label ?? severity}</span>;
}
