import { Link, useParams } from 'react-router'
import { Archive, ArrowLeft, ExternalLink, FileWarning, GitFork, Github, Globe, Siren, Star, Users } from 'lucide-react'
import { useProject } from '../api'
import { ApiError } from '../api/client'
import { DisclosureChannels } from '../components/DisclosureCard'
import { FindingsTable } from '../components/FindingsTable'
import { Card, CardHeader, CheckItem, EmptyState, ErrorState, PageHeader, Pill, ScoreBar, SeverityBadge, SeverityStack, Skeleton, StatusPill } from '../components/ui'
import { relativeTime, totalFindings } from '../lib/format'

export default function ProjectDetail() {
  const { id = '' } = useParams()
  const { data: p, error, isLoading } = useProject(id)

  if (error instanceof ApiError && error.status === 404) return <EmptyState title="Project not found" description={`No project with id “${id}”.`} />
  if (error) return <ErrorState error={error} />
  if (isLoading || !p) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-20" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-64 lg:col-span-2" />
          <Skeleton className="h-64" />
        </div>
      </div>
    )
  }

  const h = p.hygiene

  return (
    <>
      <Link to="/projects" className="mb-4 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
        <ArrowLeft className="size-3.5" /> All projects
      </Link>
      <PageHeader
        eyebrow={p.category ?? (p.wg_listed ? 'Public good' : 'Stellar project')}
        title={
          <span className="flex flex-wrap items-center gap-3">
            {p.display_name} <StatusPill status={p.activity_status} />
            {p.wg_listed && (
              <Pill tone="indigo" title="Recognized Stellar public good — listed by the SCF Public Goods Maintenance WG">
                Public good
              </Pill>
            )}
          </span>
        }
        description={p.description}
        actions={
          <>
            {p.website && (
              <a href={p.website} target="_blank" rel="noreferrer" className="btn-ghost">
                <Globe className="size-4" /> Website
              </a>
            )}
            {p.git_owner_url && (
              <a href={p.git_owner_url} target="_blank" rel="noreferrer" className="btn-ghost">
                <Github className="size-4" /> GitHub
              </a>
            )}
            <Link to={`/disclose?q=${encodeURIComponent(p.canonical_id)}`} className="btn-primary">
              <Siren className="size-4" /> Report a vulnerability
            </Link>
          </>
        }
      />

      <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-xs text-slate-500">Open findings</div>
          <div className="mt-2 flex items-center gap-3">
            <span className="text-2xl font-semibold text-white tabular-nums">{totalFindings(p.open_findings)}</span>
            <SeverityStack counts={p.open_findings} />
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-slate-500">PG Atlas dependents</div>
          <div className="mt-2">
            <span className="text-2xl font-semibold text-white tabular-nums">{p.criticality_score ?? '—'}</span>
            <span className="ml-1.5 text-xs text-slate-500">in-ecosystem</span>
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-slate-500">Adoption</div>
          <div className="mt-3">
            <ScoreBar value={p.adoption_score} label="PG Atlas adoption score, 0–100" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Users className="size-3.5" /> Pony factor
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span className="text-2xl font-semibold text-white tabular-nums">{p.pony_factor ?? '—'}</span>
            {p.pony_factor != null && p.pony_factor <= 1 && <Pill tone="amber">Single-maintainer risk</Pill>}
          </div>
        </Card>
      </div>

      <Card className="mb-4">
        <CardHeader title="Findings" subtitle="Click a row for remediation steps and the priority breakdown" icon={<FileWarning className="size-4" />} />
        <FindingsTable findings={p.findings} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Repositories" icon={<GitFork className="size-4" />} />
            <ul className="divide-y divide-white/[0.04]">
              {p.repos.map((r) => (
                <li key={r.canonical_id} className="flex items-center gap-3 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 truncate font-mono text-sm text-slate-200">
                      {r.display_name}
                      {r.archived && (
                        <Pill tone="amber">
                          <Archive className="size-3" /> Archived
                        </Pill>
                      )}
                    </div>
                    <div className="text-xs text-slate-500">
                      {r.latest_version && <span className="font-mono">v{r.latest_version}</span>}
                      {r.latest_commit_date && <span className="ml-2">pushed {relativeTime(r.latest_commit_date)}</span>}
                      {r.dependency_count > 0 && <span className="ml-2">{r.dependency_count} deps</span>}
                    </div>
                  </div>
                  {r.stars != null && (
                    <span className="hidden items-center gap-1 font-mono text-xs text-slate-400 sm:flex">
                      <Star className="size-3" /> {r.stars}
                    </span>
                  )}
                  <Pill tone={r.sbom_verified ? 'emerald' : 'slate'} title={r.sbom_verified ? 'SBOM submitted to PG Atlas via GitHub Action' : 'No verified SBOM — dependencies inferred by PG Atlas or unknown'}>
                    {r.sbom_verified ? 'PG Atlas SBOM' : 'No PG Atlas SBOM'}
                  </Pill>
                  <span className="w-16 text-right text-xs text-slate-400">{r.open_findings} findings</span>
                  {r.repo_url && (
                    <a href={r.repo_url} target="_blank" rel="noreferrer" className="text-slate-500 hover:text-slate-200" aria-label="Open repository">
                      <ExternalLink className="size-4" />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </Card>

          {p.published_advisories.length > 0 && (
            <Card>
              <CardHeader title="Advisories published by this project" subtitle="Repository GitHub Security Advisories" />
              <ul className="divide-y divide-white/[0.04]">
                {p.published_advisories.slice(0, 10).map((a) => (
                  <li key={a.ghsa_id}>
                    <a href={a.url} target="_blank" rel="noreferrer" className="flex items-center gap-3 px-5 py-3 transition hover:bg-white/[0.02]">
                      <SeverityBadge severity={a.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm text-slate-200">{a.summary}</div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {a.ghsa_id} · {a.repo}
                        </div>
                      </div>
                      <span className="text-xs text-slate-500">{relativeTime(a.published_at)}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="How to report a vulnerability" subtitle="Ranked by preference" icon={<Siren className="size-4" />} />
            <div className="p-4">
              <DisclosureChannels channels={p.disclosure} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Security practices" subtitle="Individual signals, not combined into a score" />
            <div className="space-y-2.5 p-5">
              <CheckItem ok={h.has_security_policy} label="SECURITY.md published" />
              <CheckItem ok={h.pvr_enabled} label="Private vulnerability reporting" />
              <CheckItem ok={h.has_security_txt} label="security.txt on website" />
              <CheckItem ok={h.dependency_update_tool} label="Dependabot / Renovate configured" />
              <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-white/[0.05] pt-4 text-xs">
                <div>
                  <dt className="text-slate-500">OpenSSF Scorecard</dt>
                  <dd className="mt-0.5 text-lg font-semibold text-white tabular-nums">{h.scorecard_overall?.toFixed(1) ?? '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Published advisories</dt>
                  <dd className="mt-0.5 text-lg font-semibold text-white tabular-nums">{h.published_advisories_count ?? '—'}</dd>
                  {h.last_advisory_at && <dd className="text-slate-500">last {relativeTime(h.last_advisory_at)}</dd>}
                </div>
              </dl>
              <p className="pt-2 text-[11px] text-slate-600">“unknown” means the repo has not been checked yet — not that the practice is absent.</p>
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
