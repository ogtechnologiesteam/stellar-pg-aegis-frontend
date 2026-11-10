import clsx from 'clsx'
import { useState, type ReactNode } from 'react'
import { AlertTriangle, Check, Copy, Flame, Inbox } from 'lucide-react'
import type { ActivityStatus, Confidence, Severity, SeverityCounts } from '../api/types'
import { SEVERITIES, SEVERITY_COLOR, STATUS_LABEL } from '../lib/format'

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={clsx('card', className)}>{children}</section>
}

export function CardHeader({ title, subtitle, action, icon }: { title: ReactNode; subtitle?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <header className="flex items-start justify-between gap-4 border-b border-white/[0.05] px-5 py-4">
      <div className="flex items-start gap-3">
        {icon && <div className="mt-0.5 text-indigo-300">{icon}</div>}
        <div>
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
        </div>
      </div>
      {action}
    </header>
  )
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div>
        {eyebrow && <div className="mb-2 text-xs font-medium tracking-wider text-indigo-300/80 uppercase">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold tracking-tight text-white md:text-[28px]">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}

const SEV_BADGE: Record<Severity, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  medium: 'bg-yellow-500/10 text-yellow-200 ring-yellow-500/25',
  low: 'bg-sky-500/10 text-sky-300 ring-sky-500/25',
  unknown: 'bg-slate-500/10 text-slate-400 ring-slate-500/25',
}

export function SeverityBadge({ severity, cvss }: { severity: Severity; cvss?: number | null }) {
  return (
    <span className={clsx('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold capitalize ring-1 ring-inset', SEV_BADGE[severity])}>
      <span className="size-1.5 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} />
      {severity}
      {cvss != null && <span className="font-mono font-normal opacity-70">{cvss.toFixed(1)}</span>}
    </span>
  )
}

export function Pill({ children, tone = 'slate', className, title }: { children: ReactNode; tone?: 'slate' | 'indigo' | 'emerald' | 'amber' | 'rose' | 'cyan'; className?: string; title?: string }) {
  const tones = {
    slate: 'bg-white/[0.04] text-slate-300 ring-white/10',
    indigo: 'bg-indigo-500/10 text-indigo-300 ring-indigo-500/25',
    emerald: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/25',
    amber: 'bg-amber-500/10 text-amber-300 ring-amber-500/25',
    rose: 'bg-rose-500/10 text-rose-300 ring-rose-500/25',
    cyan: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/25',
  }
  return (
    <span title={title} className={clsx('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium whitespace-nowrap ring-1 ring-inset', tones[tone], className)}>
      {children}
    </span>
  )
}

export function KevBadge() {
  return (
    <Pill tone="rose" title="Listed in CISA Known Exploited Vulnerabilities">
      <Flame className="size-3" /> KEV
    </Pill>
  )
}

const STATUS_TONE: Record<ActivityStatus, 'emerald' | 'cyan' | 'slate' | 'amber'> = { live: 'emerald', 'in-dev': 'cyan', discontinued: 'slate', 'non-responsive': 'amber' }

export function StatusPill({ status }: { status: ActivityStatus }) {
  return <Pill tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</Pill>
}

const CONF_TONE: Record<Confidence, 'emerald' | 'amber' | 'slate'> = { confirmed: 'emerald', possible: 'amber', inferred: 'slate' }
const CONF_HELP: Record<Confidence, string> = {
  confirmed: 'Exact version from a verified SBOM',
  possible: 'Only a version range is known; shown for the lowest matching version',
  inferred: 'Dependency inferred by PG Atlas registry crawl, not a submitted SBOM',
}

export function ConfidencePill({ confidence }: { confidence: Confidence }) {
  return (
    <Pill tone={CONF_TONE[confidence]} title={CONF_HELP[confidence]} className="capitalize">
      {confidence === 'inferred' ? 'PG Atlas inferred' : confidence}
    </Pill>
  )
}

export function PriorityMeter({ value }: { value: number }) {
  const color = value >= 70 ? 'from-rose-500 to-orange-400' : value >= 45 ? 'from-orange-400 to-yellow-300' : 'from-sky-500 to-cyan-300'
  return (
    <div className="flex items-center gap-2.5" title={`Priority ${value}/100`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-white/[0.06]">
        <div className={clsx('h-full rounded-full bg-gradient-to-r', color)} style={{ width: `${value}%` }} />
      </div>
      <span className="w-6 font-mono text-xs text-slate-300 tabular-nums">{value}</span>
    </div>
  )
}

export function ScoreBar({ value, label }: { value: number | null; label?: string }) {
  if (value == null) return <span className="font-mono text-xs text-slate-600" title={label}>—</span>
  return (
    <div className="flex items-center gap-2" title={label}>
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-white/[0.06]">
        <div className="h-full rounded-full bg-gradient-to-r from-indigo-400 to-cyan-300" style={{ width: `${Math.min(100, Math.round(value))}%` }} />
      </div>
      <span className="font-mono text-xs text-slate-400 tabular-nums">{Number.isInteger(value) ? value : value.toFixed(1)}</span>
    </div>
  )
}

export function SeverityStack({ counts, className }: { counts: SeverityCounts; className?: string }) {
  const total = SEVERITIES.reduce((a, s) => a + counts[s], 0)
  if (!total) return <span className="text-xs text-slate-600">None</span>
  return (
    <div className={clsx('flex items-center gap-1', className)}>
      {SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
        <span key={s} title={`${counts[s]} ${s}`} className={clsx('inline-flex h-5 min-w-5 items-center justify-center rounded px-1 font-mono text-[11px] font-semibold ring-1 ring-inset', SEV_BADGE[s])}>
          {counts[s]}
        </span>
      ))}
    </div>
  )
}

export function CheckItem({ ok, label }: { ok: boolean | null; label: string }) {
  return (
    <div className={clsx('flex items-center gap-2 text-sm', ok ? 'text-slate-200' : 'text-slate-500')}>
      <span className={clsx('grid size-5 place-items-center rounded-full', ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-white/[0.04] text-slate-600')} title={ok == null ? 'Not collected yet' : undefined}>
        {ok ? <Check className="size-3" strokeWidth={3} /> : <span className="h-px w-2 bg-current" />}
      </span>
      <span className={ok == null ? 'italic' : ''}>{label}{ok == null && <span className="ml-1.5 text-[11px] not-italic text-slate-600">unknown</span>}</span>
    </div>
  )
}

export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard.writeText(value).then(() => (setCopied(true), setTimeout(() => setCopied(false), 1500)))}
      className={clsx('grid size-8 shrink-0 cursor-pointer place-items-center rounded-lg text-slate-400 transition hover:bg-white/[0.06] hover:text-white', className)}
      aria-label="Copy to clipboard"
    >
      {copied ? <Check className="size-4 text-emerald-300" /> : <Copy className="size-4" />}
    </button>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx('animate-pulse rounded-lg bg-white/[0.05]', className)} />
}

export function EmptyState({ title, description, icon }: { title: string; description?: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="grid size-11 place-items-center rounded-2xl bg-white/[0.04] text-slate-500">{icon ?? <Inbox className="size-5" />}</div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {description && <p className="max-w-sm text-xs text-slate-500">{description}</p>}
    </div>
  )
}

export function ErrorState({ error }: { error: unknown }) {
  return <EmptyState icon={<AlertTriangle className="size-5 text-rose-300" />} title="Something went wrong" description={error instanceof Error ? error.message : String(error)} />
}

export function Segmented<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[] }) {
  return (
    <div className="inline-flex rounded-xl border border-white/[0.08] bg-ink-850 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={clsx('cursor-pointer rounded-[10px] px-3 py-1.5 text-xs font-medium transition', value === o.value ? 'bg-white/[0.08] text-white shadow-sm' : 'text-slate-400 hover:text-slate-200')}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
