import { Link } from 'react-router'
import { ArrowRight, Boxes, Crosshair, Flame, GitBranch, ShieldAlert, ShieldCheck, Timer, Wrench } from 'lucide-react'
import type { ReactNode } from 'react'
import { useFindings, useProjects, useSummary, useVulns } from '../api'
import { CoverageRing, SeverityDonut } from '../components/charts'
import { FindingsTable } from '../components/FindingsTable'
import { Card, CardHeader, ErrorState, KevBadge, PageHeader, Pill, SeverityBadge, Skeleton } from '../components/ui'
import { SEVERITIES, SEVERITY_COLOR, relativeTime, totalFindings } from '../lib/format'

function Kpi({ icon, label, value, hint, accent, to }: { icon: ReactNode; label: string; value: ReactNode; hint?: ReactNode; accent: string; to: string }) {
  return (
    <Link to={to} className="card group relative block overflow-hidden p-5 transition hover:border-indigo-400/25 hover:bg-ink-850/80">
      <div className="absolute -top-10 -right-10 size-32 rounded-full opacity-20 blur-2xl" style={{ background: accent }} />
      <div className="flex items-center gap-2 text-xs font-medium text-slate-400">
        <span className="grid size-7 place-items-center rounded-lg bg-white/[0.04]" style={{ color: accent }}>
          {icon}
        </span>
        {label}
        <ArrowRight className="ml-auto size-3.5 text-slate-600 opacity-0 transition group-hover:translate-x-0.5 group-hover:text-indigo-300 group-hover:opacity-100" />
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight text-white tabular-nums">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </Link>
  )
}

export default function Overview() {
  const summary = useSummary()
  const findings = useFindings(8, 'project')
  const vulns = useVulns({ limit: 5 })
  const gaps = useProjects({ has_policy: false, sort: 'criticality', limit: 6 })
  const kevProjects = useProjects({ kev: true, limit: 1 })
  const fixableProjects = useProjects({ fixable: true, limit: 1 })
  const pgProjects = useProjects({ wg_listed: true, limit: 1 })
  const reachableProjects = useProjects({ reachable: true, limit: 1 })
  const auditedProjects = useProjects({ audited: true, limit: 1 })

  if (summary.error) return <ErrorState error={summary.error} />
  const s = summary.data
  const ecoMax = Math.max(1, ...(s?.by_ecosystem.map((e) => e.findings) ?? [1]))

  return (
    <>
      <PageHeader
        eyebrow="Ecosystem overview"
        title="Security posture of Stellar public goods"
        description="Known vulnerabilities in tracked Stellar project dependencies — WG-recognized public goods included — ranked by how much of the ecosystem they affect, with how to report each to its maintainers."
        actions={
          <>
            <Link to="/disclose" className="btn-ghost">
              Report a vulnerability
            </Link>
            <Link to="/advisories" className="btn-primary">
              Browse advisories <ArrowRight className="size-4" />
            </Link>
          </>
        }
      />

      <div className={`grid grid-cols-2 gap-4 ${s?.reachability ? 'xl:grid-cols-6' : 'xl:grid-cols-5'}`}>
        {!s ? (
          Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-[132px] rounded-2xl" />)
        ) : (
          <>
            <Kpi icon={<ShieldAlert className="size-4" />} label="Open findings" value={totalFindings(s.open_findings)} hint={`${s.open_findings.critical} critical · ${s.open_findings.high} high · across ${s.affected_projects} projects`} accent="#f43f5e" to="/projects?sort=findings" />
            <Kpi icon={<Flame className="size-4" />} label="Known exploited (KEV)" value={s.kev_findings} hint={`Actively exploited in the wild · across ${kevProjects.data?.total ?? '…'} projects`} accent="#fb923c" to="/projects?kev=1" />
            <Kpi icon={<Wrench className="size-4" />} label="Fixable now" value={s.fixable_findings} hint={`A patched version exists upstream · across ${fixableProjects.data?.total ?? '…'} projects`} accent="#34d399" to="/projects?fixable=1" />
            <Kpi icon={<Timer className="size-4" />} label="Median advisory age" value={s.median_fixable_advisory_age_days != null ? `${s.median_fixable_advisory_age_days}d` : '—'} hint={`Snapshot ${relativeTime(s.generated_at)}`} accent="#818cf8" to="/advisories?sort=oldest" />
            {s.reachability && (
              <Kpi icon={<Crosshair className="size-4" />} label="Calls vulnerable code" value={s.reachability.called} hint={`call paths into vulnerable code confirmed — govulncheck + manual review · ${s.reachability['not-called'] + s.reachability.unflagged} cleared · across ${reachableProjects.data?.total ?? '…'} projects`} accent="#e879f9" to="/projects?reach=1" />
            )}
            <Kpi icon={<ShieldCheck className="size-4" />} label="Audited projects" value={s.audit_coverage == null ? '—' : auditedProjects.data?.total ?? '…'} hint={s.audit_coverage == null ? 'Security Portal not checked in this snapshot' : `≥1 approved Security Portal report · ${Math.round(s.audit_coverage * 100)}% of WG public goods`} accent="#fbbf24" to="/projects?audited=1" />
          </>
        )}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Findings by dependency ecosystem"
            subtitle={s ? `${s.dependencies_resolved.toLocaleString()} of ${s.dependencies_total.toLocaleString()} dependency edges resolved to a package version` : undefined}
          />
          <div className="space-y-3 p-5">
            {s ? (
              s.by_ecosystem.map((e) => (
                <div key={e.ecosystem} className="flex items-center gap-3 text-sm">
                  <span className="w-24 shrink-0 font-mono text-xs text-slate-400">{e.ecosystem}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
                    <div className="h-full rounded-full bg-gradient-to-r from-indigo-400 to-cyan-400" style={{ width: `${(e.findings / ecoMax) * 100}%` }} />
                  </div>
                  <span className="w-14 text-right font-mono text-xs text-slate-300 tabular-nums">{e.findings}</span>
                  <span className="hidden w-20 text-right text-xs text-slate-500 sm:block">{e.repos} repos</span>
                </div>
              ))
            ) : (
              <Skeleton className="h-48" />
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Severity distribution" />
          <div className="px-5 pt-3 pb-5">
            {s ? (
              <>
                <SeverityDonut counts={s.open_findings} />
                <div className="mt-3 grid grid-cols-2 gap-2">
                  {SEVERITIES.filter((sev) => s.open_findings[sev] > 0).map((sev) => (
                    <div key={sev} className="flex items-center justify-between rounded-lg bg-white/[0.02] px-2.5 py-1.5 text-xs">
                      <span className="flex items-center gap-2 text-slate-400 capitalize">
                        <span className="size-2 rounded-full" style={{ background: SEVERITY_COLOR[sev] }} />
                        {sev}
                      </span>
                      <span className="font-mono text-slate-200">{s.open_findings[sev]}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <Skeleton className="h-[260px]" />
            )}
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader title="Ecosystem readiness" subtitle={s ? `${s.projects_tracked} public goods · ${s.repos_tracked} repos · coverage counts only checked repos` : undefined} icon={<Boxes className="size-4" />} />
          <div className="grid gap-5 p-5">
            {s ? (
              <>
                <CoverageRing value={s.policy_coverage} label="Publish a SECURITY.md" color="#818cf8" />
                <CoverageRing value={s.pvr_coverage} label="GitHub private vulnerability reporting enabled" color="#22d3ee" />
                <CoverageRing value={s.sbom_coverage} label="Submit verified SBOMs to PG Atlas" color="#34d399" />
                <CoverageRing value={s.audit_coverage} label="of WG public goods have a Security Portal audit" color="#fbbf24" />
              </>
            ) : (
              <Skeleton className="h-56" />
            )}
          </div>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader
            title="Most-depended-on public goods without a security policy"
            subtitle="Highest PG Atlas criticality first — prime candidates for outreach"
            action={
              <Link to="/projects?policy=missing" className="text-xs text-indigo-300 hover:text-indigo-200">
                View all
              </Link>
            }
            icon={<GitBranch className="size-4" />}
          />
          <ul className="divide-y divide-white/[0.04]">
            {gaps.data?.items.map((p) => (
              <li key={p.canonical_id}>
                <Link to={`/projects/${encodeURIComponent(p.canonical_id)}`} className="flex items-center gap-4 px-5 py-3 transition hover:bg-white/[0.02]">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-slate-100">{p.display_name}</div>
                    <div className="text-xs text-slate-500">{p.category ?? 'Uncategorized'}</div>
                  </div>
                  {p.hygiene.pvr_enabled ? (
                    <Pill tone="cyan">PVR only</Pill>
                  ) : p.hygiene.pvr_enabled === false ? (
                    <Pill tone="amber">No channel</Pill>
                  ) : (
                    <Pill tone="slate" title="GitHub enrichment hasn't checked this project's repos for PVR yet">Not checked</Pill>
                  )}
                  <span className="font-mono text-xs text-slate-400 tabular-nums" title="PG Atlas criticality — in-ecosystem dependents">
                    {p.criticality_score ?? '—'} dependents
                  </span>
                </Link>
              </li>
            )) ?? <Skeleton className="m-5 h-48" />}
          </ul>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Top priority findings" subtitle="Highest-priority open finding per public good — severity × criticality × exploitability × exposure" action={<Link to="/projects" className="text-xs text-indigo-300 hover:text-indigo-200">All projects</Link>} />
          {findings.data ? <FindingsTable findings={findings.data.items} showProject expandable={false} /> : <Skeleton className="m-5 h-64" />}
        </Card>
        <Card>
          <CardHeader title="Widest-reaching advisories" action={<Link to="/advisories" className="text-xs text-indigo-300 hover:text-indigo-200">View all</Link>} />
          <ul className="divide-y divide-white/[0.04]">
            {vulns.data?.items.map((v) => (
              <li key={v.id}>
                <Link to={`/advisories/${encodeURIComponent(v.id)}`} className="block px-5 py-3.5 transition hover:bg-white/[0.02]">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={v.severity} cvss={v.cvss} />
                    {v.kev && <KevBadge />}
                    <span className="ml-auto text-[11px] text-slate-500">{relativeTime(v.published)}</span>
                  </div>
                  <div className="mt-1.5 truncate text-sm text-slate-200">{v.summary}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                    {v.ecosystem}/{v.package} · {v.exposed_projects} projects exposed
                  </div>
                </Link>
              </li>
            )) ?? <Skeleton className="m-5 h-64" />}
          </ul>
        </Card>
      </div>

      {s?.pg_atlas && (
        <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-slate-500">
          <span className="flex items-center gap-1.5">
            <ShieldCheck className="size-3.5 text-emerald-400/70" />
            PG Atlas inventory: {s.pg_atlas.total_projects.toLocaleString()} projects · {s.pg_atlas.total_dependency_edges.toLocaleString()} dependency edges — Aegis tracks {s.projects_tracked} Stellar projects, {pgProjects.data?.total ?? '…'} recognized public goods
          </span>
          <span>Snapshot generated {relativeTime(s.generated_at)} · sources: {s.sources.join(', ')}</span>
        </div>
      )}
    </>
  )
}
