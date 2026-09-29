import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { fmtTime } from '../lib/format';
import type { TrendPoint } from '../lib/types';
import { Empty } from './Panel';

// exec · open · connect 3계열 + 위반 (최근 5분, 5초 단위)
const series = [
  { key: 'exec', name: 'exec', color: '#7c3aed' },
  { key: 'open', name: 'open', color: '#0284c7' },
  { key: 'connect', name: 'connect', color: '#0d9488' },
  { key: 'violations', name: '위반', color: '#dc2626' },
] as const;

export function TrendChart({ data }: { data: TrendPoint[] | undefined }) {
  if (!data?.length) return <Empty>추이 데이터 대기 중</Empty>;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 12, right: 16, bottom: 4, left: -8 }}>
        <CartesianGrid stroke="#f1f5f9" vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(t: string) => fmtTime(t).slice(0, 5)}
          minTickGap={48}
          tick={{ fontSize: 11, fill: '#64748b' }}
          axisLine={{ stroke: '#e2e8f0' }}
          tickLine={false}
        />
        <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} width={40} />
        <Tooltip
          labelFormatter={(t) => fmtTime(String(t))}
          contentStyle={{ fontSize: 12, borderRadius: 6, borderColor: '#e2e8f0' }}
        />
        <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />
        {series.map((s) => (
          <Line
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.name}
            stroke={s.color}
            strokeWidth={s.key === 'violations' ? 2 : 1.5}
            dot={false}
            isAnimationActive={false}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}
