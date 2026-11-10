import { Link, useSearchParams } from 'react-router'
import { ArrowRight, Search } from 'lucide-react'
import type { Severity } from '../api/types'
import { useSummary, useVulns } from '../api'
import { Card, EmptyState, ErrorState, KevBadge, PageHeader, Pill, Segmented, SeverityBadge, Skeleton } from '../components/ui'
import { SEVERITIES, relativeTime } from '../lib/format'

export default function Advisories() {
  const [params, setParams] = useSearchParams()
  const search = params.get('search') ?? ''
  const severity = (params.get('severity') ?? 'all') as Severity | 'all'
  const ecosystem = params.get('ecosystem') ?? ''
  const { data: summary } = useSummary()

  const set = (k: string, v: string, fallback = '') =>
    setParams(
      (p) => {
        if (v === fallback) p.delete(k)
        else p.set(k, v)
        return p
      },
      { replace: true },
    )

  const { data, error, isLoading, isPlaceholderData } = useVulns({ search: search || undefined, severity: severity === 'all' ? undefined : severity, ecosystem: ecosystem || undefined, limit: 100 })

  return (
    <>
      <PageHeader eyebrow="Vulnerability intelligence" title="Advisories" description="OSV advisories that affect at least one Stellar public good, with how far each spreads through the PG Atlas dependency graph." />

      <Card className="mb-4 flex flex-col gap-3 p-3 lg:flex-row lg:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500" />
          <input value={search} onChange={(e) => set('search', e.target.value)} placeholder="Advisory ID, alias or package" className="input pl-9" aria-label="Filter advisories" />
        </div>
        <select value={ecosystem} onChange={(e) => set('ecosystem', e.target.value)} className="input w-full lg:w-44" aria-label="Ecosystem">
          <option value="">All ecosystems</option>
          {(summary?.by_ecosystem ?? []).map((e) => (
            <option key={e.ecosystem}>{e.ecosystem}</option>
          ))}
        </select>
        <Segmented<Severity | 'all'> value={severity} onChange={(v) => set('severity', v, 'all')} options={[{ value: 'all', label: 'All' }, ...SEVERITIES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))]} />
      </Card>

      {error ? (
        <ErrorState error={error} />
      ) : isLoading ? (
        <div className="grid gap-3 md:grid-cols-2">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-36 rounded-2xl" />
          ))}
        </div>
      ) : !data?.items.length ? (
        <Card>
          <EmptyState title="No advisories match your filters" />
        </Card>
      ) : (
        <div className={`grid gap-3 md:grid-cols-2 ${isPlaceholderData ? 'opacity-70' : ''}`}>
          {data.items.map((v) => (
            <Link key={v.id} to={`/advisories/${encodeURIComponent(v.id)}`} className="card group block p-5 transition hover:border-indigo-400/25 hover:bg-ink-850/80">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={v.severity} cvss={v.cvss} />
                {v.kev && <KevBadge />}
                <Pill>{v.ecosystem}</Pill>
                <span className="ml-auto font-mono text-[11px] text-slate-500">{v.id}</span>
              </div>
              <h3 className="mt-3 text-[15px] font-medium text-slate-100">{v.summary}</h3>
              <div className="mt-1 font-mono text-xs text-slate-400">
                {v.package} <span className="text-slate-600">{v.affected_range}</span>
              </div>
              <div className="mt-4 flex items-center gap-4 text-xs text-slate-500">
                <span>
                  <span className="font-semibold text-slate-200">{v.exposed_projects}</span> projects exposed
                </span>
                <span>{v.fixed_versions.length ? <span className="text-emerald-300">Fix {v.fixed_versions[0]}</span> : <span className="text-amber-300">No fix</span>}</span>
                <span>Published {relativeTime(v.published)}</span>
                <ArrowRight className="ml-auto size-4 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-indigo-300" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </>
  )
}
