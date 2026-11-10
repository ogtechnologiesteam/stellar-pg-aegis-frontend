import { useNavigate, useSearchParams } from 'react-router'
import { Github, Search, ShieldCheck, ShieldOff } from 'lucide-react'
import type { ActivityStatus, ProjectQuery } from '../api/types'
import { useProjects } from '../api'
import { Card, EmptyState, ErrorState, PageHeader, Pill, PriorityMeter, Segmented, SeverityStack, Skeleton, StatusPill } from '../components/ui'
import { STATUS_LABEL } from '../lib/format'

type PolicyFilter = 'all' | 'present' | 'missing'
type Sort = NonNullable<ProjectQuery['sort']>

export default function Projects() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const search = params.get('search') ?? ''
  const status = (params.get('status') ?? '') as ActivityStatus | ''
  const policy = (params.get('policy') ?? 'all') as PolicyFilter
  const sort = (params.get('sort') ?? 'priority') as Sort

  const set = (k: string, v: string, fallback = '') =>
    setParams(
      (p) => {
        if (v === fallback) p.delete(k)
        else p.set(k, v)
        return p
      },
      { replace: true },
    )

  const { data, error, isLoading, isPlaceholderData } = useProjects({
    search: search || undefined,
    activity_status: status || undefined,
    has_policy: policy === 'all' ? undefined : policy === 'present',
    sort,
    limit: 200,
  })

  return (
    <>
      <PageHeader eyebrow="Inventory" title="Projects" description="SCF public goods synced from PG Atlas, with each one's open findings, disclosure channels and security practices." />

      <Card className="mb-4 flex flex-col gap-3 p-3 lg:flex-row lg:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500" />
          <input value={search} onChange={(e) => set('search', e.target.value)} placeholder="Filter by name or category" className="input pl-9" aria-label="Filter projects" />
        </div>
        <select value={status} onChange={(e) => set('status', e.target.value)} className="input w-full lg:w-48" aria-label="Activity status">
          <option value="">Any status</option>
          {(Object.keys(STATUS_LABEL) as ActivityStatus[]).map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
        <Segmented<PolicyFilter>
          value={policy}
          onChange={(v) => set('policy', v, 'all')}
          options={[
            { value: 'all', label: 'All' },
            { value: 'present', label: 'Has policy' },
            { value: 'missing', label: 'No policy' },
          ]}
        />
        <select value={sort} onChange={(e) => set('sort', e.target.value, 'priority')} className="input w-full lg:w-44" aria-label="Sort by">
          <option value="priority">Sort: priority</option>
          <option value="findings">Sort: findings</option>
          <option value="criticality">Sort: criticality</option>
          <option value="name">Sort: name</option>
        </select>
      </Card>

      <Card className={isPlaceholderData ? 'opacity-70 transition' : 'transition'}>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <div className="space-y-2 p-5">
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : !data?.items.length ? (
          <EmptyState title="No projects match your filters" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead className="border-b border-white/[0.05]">
                <tr>
                  <th className="th">Project</th>
                  <th className="th">Status</th>
                  <th className="th">Open findings</th>
                  <th className="th">Disclosure</th>
                  <th className="th">Dependents</th>
                  <th className="th">Pony factor</th>
                  <th className="th">Scorecard</th>
                  <th className="th">Max priority</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {data.items.map((p) => (
                  <tr key={p.canonical_id} className="cursor-pointer transition hover:bg-white/[0.025]" onClick={() => navigate(`/projects/${encodeURIComponent(p.canonical_id)}`)}>
                    <td className="td">
                      <div className="flex items-center gap-3">
                        <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-indigo-500/25 to-cyan-500/10 text-sm font-semibold text-indigo-100 ring-1 ring-white/10">
                          {p.display_name.replace(/^stellar[\s-]?/i, '').charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="font-medium text-slate-100">{p.display_name}</div>
                          <div className="text-xs text-slate-500">
                            {p.category ?? 'Uncategorized'} · {p.repo_count} repo{p.repo_count === 1 ? '' : 's'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="td">
                      <StatusPill status={p.activity_status} />
                    </td>
                    <td className="td">
                      <SeverityStack counts={p.open_findings} />
                    </td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {p.hygiene.has_security_policy ? (
                          <Pill tone="emerald">
                            <ShieldCheck className="size-3" /> Policy
                          </Pill>
                        ) : p.hygiene.has_security_policy === false ? (
                          <Pill tone="amber">
                            <ShieldOff className="size-3" /> No policy
                          </Pill>
                        ) : (
                          <Pill title="Repos not yet checked — run data:refresh to extend GitHub coverage">Unknown</Pill>
                        )}
                        {p.hygiene.pvr_enabled && (
                          <Pill tone="cyan">
                            <Github className="size-3" /> PVR
                          </Pill>
                        )}
                      </div>
                    </td>
                    <td className="td">
                      <span className="font-mono text-xs text-slate-300 tabular-nums" title="PG Atlas criticality — transitive in-ecosystem dependents">
                        {p.criticality_score ?? '—'}
                      </span>
                    </td>
                    <td className="td">
                      <span className={p.pony_factor != null && p.pony_factor <= 1 ? 'font-mono text-amber-300' : 'font-mono text-slate-300'} title={p.pony_factor != null && p.pony_factor <= 1 ? 'Single-maintainer risk' : undefined}>
                        {p.pony_factor ?? '—'}
                      </span>
                    </td>
                    <td className="td font-mono text-xs text-slate-300">{p.hygiene.scorecard_overall?.toFixed(1) ?? '—'}</td>
                    <td className="td">
                      <PriorityMeter value={p.max_priority} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="border-t border-white/[0.04] px-5 py-3 text-xs text-slate-500">{data.total} projects</div>
          </div>
        )}
      </Card>
    </>
  )
}
