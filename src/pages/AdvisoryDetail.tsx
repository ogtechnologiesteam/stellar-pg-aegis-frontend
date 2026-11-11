import { Link, useParams } from 'react-router'
import { ArrowLeft, ExternalLink, Radar } from 'lucide-react'
import { useVulnExposure } from '../api'
import { ApiError } from '../api/client'
import { BlastRadius } from '../components/BlastRadius'
import { Card, CardHeader, EmptyState, ErrorState, KevBadge, PageHeader, Pill, SeverityBadge, Skeleton } from '../components/ui'
import { pct, shortDate } from '../lib/format'

export default function AdvisoryDetail() {
  const { id = '' } = useParams()
  const { data, error, isLoading } = useVulnExposure(id)

  if (error instanceof ApiError && error.status === 404) return <EmptyState title="Advisory not found" description={`No advisory with id “${id}”.`} />
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Skeleton className="h-[480px] rounded-2xl" />

  const { vuln: v, exposures } = data
  const direct = exposures.filter((e) => e.depth === 1).length
  const pgs = new Set(exposures.map((e) => e.project_id ?? e.repo_id)).size

  return (
    <>
      <Link to="/advisories" className="mb-4 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
        <ArrowLeft className="size-3.5" /> All advisories
      </Link>
      <PageHeader
        eyebrow={
          <span className="font-mono normal-case">
            {v.id} {v.aliases.length > 0 && <span className="text-slate-500">· {v.aliases.slice(0, 4).join(' · ')}{v.aliases.length > 4 ? ' …' : ''}</span>}
          </span>
        }
        title={v.summary}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={v.severity} cvss={v.cvss} />
            {v.kev && <KevBadge />}
            <Pill>{v.ecosystem}</Pill>
            <span className="font-mono text-xs text-slate-300">{v.package}</span>
          </span>
        }
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader title="Blast radius" subtitle={`${pgs} public goods · ${exposures.length} repos exposed · ${direct} direct, ${exposures.length - direct} downstream`} icon={<Radar className="size-4" />} />
          <div className="p-4">{exposures.length ? <BlastRadius pkg={v.package} severity={v.severity} exposures={exposures} /> : <EmptyState title="No exposure" />}</div>
        </Card>

        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Details" />
            <div className="space-y-4 p-5">
              <p className="text-sm leading-relaxed text-slate-300">{v.details}</p>
              <dl className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <dt className="text-slate-500">Affected</dt>
                  <dd className="mt-0.5 font-mono text-slate-200">{v.affected_range}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Fixed in</dt>
                  <dd className="mt-0.5 font-mono">{v.fixed_versions.length ? <span className="text-emerald-300">{v.fixed_versions.join(', ')}</span> : <span className="text-amber-300">No fix available</span>}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">EPSS</dt>
                  <dd className="mt-0.5 text-slate-200">{v.epss != null ? `${pct(v.epss, 1)} probability of exploitation` : '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Published · modified</dt>
                  <dd className="mt-0.5 text-slate-200">
                    {shortDate(v.published)} · {shortDate(v.modified)}
                  </dd>
                </div>
                {v.cvss_vector && (
                  <div className="col-span-2">
                    <dt className="text-slate-500">CVSS vector</dt>
                    <dd className="mt-0.5 font-mono text-[11px] break-all text-slate-400">{v.cvss_vector}</dd>
                  </div>
                )}
              </dl>
              <div className="space-y-1.5 border-t border-white/[0.05] pt-4">
                {v.references.map((r) => (
                  <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200">
                    <Pill className="w-20 justify-center">{r.type}</Pill>
                    <span className="truncate">{r.url}</span>
                    <ExternalLink className="size-3 shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          </Card>
        </div>
      </div>

      <Card className="mt-4">
        <CardHeader title="Exposed public goods" subtitle="Ordered by depth, then PG Atlas criticality" />
        <ul className="divide-y divide-white/[0.04] md:hidden">
          {exposures.map((e) => (
            <li key={e.repo_id} className="px-4 py-3.5">
              <div className="flex items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-slate-100">{e.repo_name}</div>
                  <div className="truncate font-mono text-[11px] text-slate-500">{e.repo_id}</div>
                </div>
                <Pill tone={e.depth === 1 ? 'rose' : 'slate'}>{e.depth === 1 ? 'Affected' : `Depth ${e.depth}`}</Pill>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-slate-400">
                {e.project_id ? (
                  <Link to={`/projects/${encodeURIComponent(e.project_id)}`} className="font-medium text-slate-200 hover:text-white">
                    {e.project_name}
                  </Link>
                ) : (
                  <Pill>Not a public good</Pill>
                )}
                {e.via && <span className="font-mono">via {e.via}</span>}
                <span className="font-mono tabular-nums">{e.criticality_score ?? '—'} dependents</span>
                {e.project_id && (
                  <Link to={`/disclose?q=${encodeURIComponent(e.project_id)}`} className="ml-auto text-indigo-300 hover:text-indigo-200">
                    Disclosure channel →
                  </Link>
                )}
              </div>
            </li>
          ))}
        </ul>
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[640px]">
            <thead className="border-b border-white/[0.05]">
              <tr>
                <th className="th">Repo</th>
                <th className="th">Public good</th>
                <th className="th">Exposure</th>
                <th className="th">Via</th>
                <th className="th">Dependents</th>
                <th className="th" />
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {exposures.map((e) => (
                <tr key={e.repo_id} className="transition hover:bg-white/[0.02]">
                  <td className="td">
                    <div className="font-medium text-slate-100">{e.repo_name}</div>
                    <div className="font-mono text-[11px] text-slate-500">{e.repo_id}</div>
                  </td>
                  <td className="td">
                    {e.project_id ? (
                      <Link to={`/projects/${encodeURIComponent(e.project_id)}`} className="text-sm text-slate-200 hover:text-white">
                        {e.project_name}
                      </Link>
                    ) : (
                      <Pill>Not a public good</Pill>
                    )}
                  </td>
                  <td className="td">
                    <Pill tone={e.depth === 1 ? 'rose' : 'slate'}>{e.depth === 1 ? 'Affected' : `Depth ${e.depth}`}</Pill>
                  </td>
                  <td className="td font-mono text-xs text-slate-400">{e.via ?? '—'}</td>
                  <td className="td font-mono text-xs text-slate-300 tabular-nums">{e.criticality_score ?? '—'}</td>
                  <td className="td text-right">
                    {e.project_id && (
                      <Link to={`/disclose?q=${encodeURIComponent(e.project_id)}`} className="text-xs text-indigo-300 hover:text-indigo-200">
                        Disclosure channel →
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}
