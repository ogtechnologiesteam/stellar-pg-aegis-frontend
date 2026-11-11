import { useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import type { Exposure, Severity } from '../api/types'
import { SEVERITY_COLOR } from '../lib/format'
import { logNorm } from '../lib/priority'

const SIZE = 520
const C = SIZE / 2
const MAX_RING_GAP = 92
const DEPTH_COLOR = ['#f43f5e', '#fb923c', '#a78bfa']

interface Node extends Exposure {
  x: number
  y: number
  r: number
}

export function BlastRadius({ pkg, severity, exposures }: { pkg: string; severity: Severity; exposures: Exposure[] }) {
  const navigate = useNavigate()
  const [hover, setHover] = useState<string | null>(null)
  const pointerType = useRef('mouse')

  const { nodes, edges, maxDepth, gap } = useMemo(() => {
    const byDepth = new Map<number, Exposure[]>()
    exposures.forEach((e) => byDepth.set(e.depth, [...(byDepth.get(e.depth) ?? []), e]))
    const maxDepth = Math.max(1, ...byDepth.keys())
    const gap = Math.min(MAX_RING_GAP, (C - 44) / maxDepth)
    const maxCrit = Math.max(0, ...exposures.map((e) => e.criticality_score ?? 0))
    const nodes: Node[] = []
    for (const [depth, list] of [...byDepth.entries()].sort(([a], [b]) => a - b)) {
      const radius = depth * gap
      const offset = depth * 0.6
      list.forEach((e, i) => {
        const a = offset + (i / list.length) * Math.PI * 2
        nodes.push({ ...e, x: C + radius * Math.cos(a), y: C + radius * Math.sin(a), r: 7 + logNorm(e.criticality_score, maxCrit) * 12 })
      })
    }
    const byName = new Map(nodes.map((n) => [n.repo_name, n]))
    const edges = nodes.map((n) => {
      const from = n.via ? byName.get(n.via) : undefined
      return { id: n.repo_id, x1: from?.x ?? C, y1: from?.y ?? C, x2: n.x, y2: n.y, from: from?.repo_id ?? 'root' }
    })
    return { nodes, edges, maxDepth, gap }
  }, [exposures])

  const active = hover ? nodes.find((n) => n.repo_id === hover) : null
  const color = SEVERITY_COLOR[severity]

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="mx-auto w-full max-w-[520px]" role="img" aria-label={`Blast radius of ${pkg}`}>
        <defs>
          <radialGradient id="br-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={color} stopOpacity="0.55" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </radialGradient>
        </defs>
        {Array.from({ length: maxDepth }, (_, i) => (
          <g key={i}>
            <circle cx={C} cy={C} r={(i + 1) * gap} fill="none" stroke="var(--viz-line)" strokeDasharray="3 6" />
            <text x={C + 6} y={C - (i + 1) * gap - 6} fill="var(--viz-label)" fontSize="10">
              {i === 0 ? 'affected' : `depth ${i + 1}`}
            </text>
          </g>
        ))}
        {edges.map((e) => {
          const lit = hover === e.id || hover === e.from
          return <line key={e.id} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke={lit ? 'var(--viz-edge-lit)' : 'var(--viz-edge)'} strokeWidth={lit ? 1.6 : 1} />
        })}
        <circle cx={C} cy={C} r={Math.min(56, gap * 0.7)} fill="url(#br-core)" />
        <circle cx={C} cy={C} r={20} fill="var(--color-ink-900)" stroke={color} strokeWidth={2} />
        <text x={C} y={C + 4} textAnchor="middle" fill="var(--color-slate-100)" fontSize="11" fontWeight={600}>
          pkg
        </text>
        {nodes.map((n) => (
          <g
            key={n.repo_id}
            className="cursor-pointer"
            onPointerDown={(e) => (pointerType.current = e.pointerType)}
            onMouseEnter={() => setHover(n.repo_id)}
            onMouseLeave={() => setHover(null)}
            onClick={() => {
              // Touch synthesizes mouseenter before click, so gate on pointerType:
              // first tap reveals the node details, second tap navigates.
              if (pointerType.current === 'touch' && hover !== n.repo_id) {
                setHover(n.repo_id)
              } else if (n.project_id) {
                navigate(`/projects/${encodeURIComponent(n.project_id)}`)
              }
            }}
          >
            <circle cx={n.x} cy={n.y} r={n.r + 6} fill={DEPTH_COLOR[Math.min(n.depth - 1, 2)]} opacity={hover === n.repo_id ? 0.25 : 0.1} />
            <circle cx={n.x} cy={n.y} r={n.r} fill="var(--color-ink-850)" stroke={DEPTH_COLOR[Math.min(n.depth - 1, 2)]} strokeWidth={2} strokeDasharray={n.project_id ? undefined : '3 3'} />
            <text x={n.x} y={n.y + n.r + 14} textAnchor="middle" fill={hover === n.repo_id ? 'var(--color-slate-100)' : 'var(--color-slate-400)'} fontSize="10.5">
              {n.repo_name.length > 20 ? `${n.repo_name.slice(0, 19)}…` : n.repo_name}
            </text>
          </g>
        ))}
      </svg>
      <div className="pointer-events-none absolute top-2 left-2 rounded-lg border border-white/[0.06] bg-ink-900/90 px-3 py-2 text-xs text-slate-400 backdrop-blur">
        {active ? (
          <>
            <div className="font-medium text-white">{active.project_name ?? active.repo_name}</div>
            <div>
              Depth {active.depth}
              {active.via ? ` via ${active.via}` : ''} · {active.criticality_score ?? 0} downstream dependents
            </div>
          </>
        ) : (
          <>
            <div className="font-mono text-slate-200">{pkg}</div>
            <div>Node size = PG Atlas dependents · dashed = outside public goods</div>
          </>
        )}
      </div>
    </div>
  )
}
