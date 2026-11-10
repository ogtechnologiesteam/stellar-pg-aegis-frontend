import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { SeverityCounts } from '../api/types'
import { SEVERITIES, SEVERITY_COLOR } from '../lib/format'

const tooltipStyle = {
  contentStyle: { background: '#0f152a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, fontSize: 12, color: '#e2e8f0' },
  labelStyle: { color: '#94a3b8', marginBottom: 4 },
  itemStyle: { textTransform: 'capitalize' as const, padding: 0 },
}

export function SeverityDonut({ counts }: { counts: SeverityCounts }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s] }))
  const total = data.reduce((a, d) => a + d.value, 0)
  return (
    <div className="relative h-[180px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie isAnimationActive={false} data={data} dataKey="value" innerRadius={58} outerRadius={78} paddingAngle={3} stroke="none" startAngle={90} endAngle={-270}>
            {data.map((d) => (
              <Cell key={d.name} fill={SEVERITY_COLOR[d.name]} />
            ))}
          </Pie>
          <Tooltip {...tooltipStyle} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-3xl font-semibold text-white tabular-nums">{total}</div>
          <div className="text-[11px] tracking-wider text-slate-500 uppercase">open findings</div>
        </div>
      </div>
    </div>
  )
}

export function CoverageRing({ value, label, color = '#818cf8' }: { value: number | null; label: string; color?: string }) {
  const r = 26
  const c = 2 * Math.PI * r
  return (
    <div className="flex items-center gap-3">
      <svg viewBox="0 0 64 64" className="size-16 -rotate-90">
        <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
        {value != null && <circle cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={`${c * value} ${c}`} />}
      </svg>
      <div>
        <div className="text-xl font-semibold text-white tabular-nums">{value == null ? '—' : `${Math.round(value * 100)}%`}</div>
        <div className="text-xs text-slate-500">{label}</div>
      </div>
    </div>
  )
}
