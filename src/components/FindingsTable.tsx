import clsx from 'clsx'
import { Fragment, useState } from 'react'
import { Link } from 'react-router'
import { ChevronRight, Terminal, Wrench } from 'lucide-react'
import type { Finding, PriorityBreakdown } from '../api/types'
import { PRIORITY_WEIGHTS } from '../lib/priority'
import { relativeTime } from '../lib/format'
import { ConfidencePill, CopyButton, EmptyState, KevBadge, Pill, PriorityMeter, ReachabilityPill, SeverityBadge } from './ui'

const BREAKDOWN_LABEL: Record<keyof PriorityBreakdown, string> = {
  severity: 'Severity (CVSS)',
  criticality: 'PG Atlas criticality',
  exploitability: 'Exploitability (KEV / EPSS)',
  exposure: 'Exposure depth',
  fix_available: 'Fix available',
  confidence_penalty: 'Confidence penalty',
}

function Breakdown({ b }: { b: PriorityBreakdown }) {
  return (
    <div className="space-y-1.5">
      {(Object.keys(BREAKDOWN_LABEL) as (keyof PriorityBreakdown)[]).map((k) => {
        const v = b[k]
        const max = PRIORITY_WEIGHTS[k]
        return (
          <div key={k} className="flex items-center gap-3 text-xs">
            <span className="w-44 text-slate-400">{BREAKDOWN_LABEL[k]}</span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
              <div className={clsx('h-full rounded-full', v < 0 ? 'bg-slate-500' : 'bg-indigo-400')} style={{ width: `${(Math.abs(v) / max) * 100}%` }} />
            </div>
            <span className="w-12 text-right font-mono text-slate-300 tabular-nums">
              {v >= 0 ? '+' : '−'}
              {Math.abs(v).toFixed(1)}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function Remediation({ f }: { f: Finding }) {
  return (
    <div className="grid gap-6 bg-ink-950/40 px-5 py-5 md:grid-cols-2">
      <div className="space-y-3">
        <h4 className="flex items-center gap-2 text-xs font-semibold tracking-wider text-slate-400 uppercase">
          <Wrench className="size-3.5" /> Remediation
        </h4>
        {f.fixed_versions.length ? (
          <>
            <p className="text-sm text-slate-300">
              Upgrade <span className="font-mono text-white">{f.package.name}</span> to <span className="font-mono text-emerald-300">{f.fixed_versions[0]}</span> or later.
              {f.package.resolution === 'range' && ` Declared range is ${f.package.version_range} — this finding covers the lowest matching version.`}
              {f.source === 'inferred-shadow' && ' This dependency was inferred by PG Atlas, so confirm it actually ships before prioritizing.'}
            </p>
            {f.upgrade_hint && (
              <div className="flex items-center gap-2 rounded-xl border border-white/[0.06] bg-ink-900 py-1 pr-1 pl-3">
                <Terminal className="size-3.5 shrink-0 text-slate-500" />
                <code className="flex-1 overflow-x-auto font-mono text-xs whitespace-nowrap text-cyan-200">{f.upgrade_hint}</code>
                <CopyButton value={f.upgrade_hint} />
              </div>
            )}
          </>
        ) : (
          <p className="text-sm text-amber-200/90">No patched version is available. Review the advisory for workarounds, or consider replacing the dependency.</p>
        )}
        <div className="flex flex-wrap gap-2 pt-1 text-xs">
          <Link to={`/advisories/${f.vuln_id}`} className="btn-ghost h-8 text-xs">
            View advisory &amp; blast radius
          </Link>
        </div>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 pt-2 text-xs">
          <dt className="text-slate-500">Package URL</dt>
          <dd className="truncate font-mono text-slate-300" title={f.package.purl}>
            {f.package.purl}
          </dd>
          <dt className="text-slate-500">Version resolution</dt>
          <dd className="text-slate-300 capitalize">{f.package.resolution}</dd>
          <dt className="text-slate-500">Repository</dt>
          <dd className="truncate font-mono text-slate-300" title={f.repo_id}>
            {f.repo_name}
          </dd>
          <dt className="text-slate-500">Advisory published</dt>
          <dd className="text-slate-300">{relativeTime(f.advisory_published)}</dd>
          {f.package.ecosystem === 'Go' && (
            <>
              <dt className="text-slate-500">Reachability</dt>
              <dd className="min-w-0 text-slate-300">
                {f.reachability === 'called' ? (
                  <>
                    calls vulnerable code
                    {f.reachability_trace && (
                      <span className="block truncate font-mono text-[11px] text-slate-500" title={f.reachability_trace}>
                        {f.reachability_trace}
                      </span>
                    )}
                  </>
                ) : f.reachability === 'not-called' ? (
                  'no call path found (govulncheck)'
                ) : f.reachability === 'unflagged' ? (
                  'not flagged by govulncheck at HEAD'
                ) : (
                  'not analyzed'
                )}
              </dd>
            </>
          )}
        </dl>
      </div>
      <div className="space-y-3">
        <h4 className="text-xs font-semibold tracking-wider text-slate-400 uppercase">Priority breakdown · {f.priority}/100</h4>
        <Breakdown b={f.priority_breakdown} />
      </div>
    </div>
  )
}

export function FindingsTable({ findings, showProject = false, expandable = true }: { findings: Finding[]; showProject?: boolean; expandable?: boolean }) {
  const [open, setOpen] = useState<string | null>(null)
  if (!findings.length) return <EmptyState title="No open findings" description="No known vulnerabilities match this project's dependencies." />

  return (
    <>
      <ul className="divide-y divide-white/[0.04] md:hidden">
        {findings.map((f) => {
          const isOpen = open === f.id
          return (
            <li key={f.id}>
              <div className="px-4 py-3.5">
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={f.severity} cvss={f.cvss} />
                      {f.kev && <KevBadge />}
                      {f.kind && f.kind !== 'vulnerability' && <Pill tone={f.kind === 'malware' ? 'rose' : 'amber'}>{f.kind}</Pill>}
                    </div>
                    <div className="mt-1.5 text-sm text-slate-200">{f.summary}</div>
                  </div>
                  <PriorityMeter value={f.priority} />
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
                  <Link to={`/advisories/${f.vuln_id}`} className="font-mono text-indigo-300 hover:text-indigo-200">
                    {f.vuln_id}
                  </Link>
                  {showProject && (
                    <Link to={`/projects/${f.project_id}`} className="font-medium text-slate-200 hover:text-white">
                      {f.project_name}
                    </Link>
                  )}
                  <span className="font-mono text-slate-500">
                    {f.package.ecosystem}/{f.package.name} {f.package.version}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <Pill tone={f.source === 'verified-sbom' ? 'emerald' : f.source === 'govulncheck' ? 'cyan' : 'slate'} title={f.source === 'verified-sbom' ? 'Declared in an SBOM submitted to PG Atlas' : f.source === 'govulncheck' ? 'Detected by govulncheck from the repo’s resolved modules — not present in PG Atlas edges' : 'Inferred from PG Atlas registry crawl'}>
                    {f.source === 'verified-sbom' ? 'PG Atlas SBOM' : f.source === 'govulncheck' ? 'govulncheck' : 'PG Atlas inferred'}
                  </Pill>
                  <ConfidencePill confidence={f.confidence} />
                  <ReachabilityPill reachability={f.reachability} trace={f.reachability_trace} />
                  <span className="font-mono text-xs">{f.fixed_versions[0] ? <span className="text-emerald-300">→ {f.fixed_versions[0]}</span> : <span className="text-amber-300">no fix</span>}</span>
                  {expandable && (
                    <button type="button" onClick={() => setOpen(isOpen ? null : f.id)} className="ml-auto inline-flex cursor-pointer items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-indigo-300 transition hover:bg-white/[0.04] hover:text-indigo-200" aria-expanded={isOpen}>
                      Details
                      <ChevronRight className={clsx('size-3.5 transition', isOpen && 'rotate-90')} />
                    </button>
                  )}
                </div>
              </div>
              {expandable && isOpen && (
                <div className="border-t border-white/[0.04]">
                  <Remediation f={f} />
                </div>
              )}
            </li>
          )
        })}
      </ul>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[760px]">
        <thead className="border-b border-white/[0.05]">
          <tr>
            {expandable && <th className="th w-8" />}
            <th className="th">Advisory</th>
            {showProject && <th className="th">Project</th>}
            <th className="th">Package</th>
            <th className="th">Severity</th>
            <th className="th">Source</th>
            <th className="th">Confidence</th>
            <th className="th">Fix</th>
            <th className="th">Priority</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {findings.map((f) => {
            const isOpen = open === f.id
            return (
              <Fragment key={f.id}>
                <tr className={clsx('transition hover:bg-white/[0.02]', expandable && 'cursor-pointer', isOpen && 'bg-white/[0.03]')} onClick={() => expandable && setOpen(isOpen ? null : f.id)}>
                  {expandable && (
                    <td className="td pr-0">
                      <ChevronRight className={clsx('size-4 text-slate-500 transition', isOpen && 'rotate-90 text-slate-200')} />
                    </td>
                  )}
                  <td className="td">
                    <Link to={`/advisories/${f.vuln_id}`} onClick={(e) => e.stopPropagation()} className="font-mono text-xs text-indigo-300 hover:text-indigo-200">
                      {f.vuln_id}
                    </Link>
                    <div className="mt-0.5 max-w-xs truncate text-xs text-slate-400">{f.summary}</div>
                  </td>
                  {showProject && (
                    <td className="td">
                      <Link to={`/projects/${f.project_id}`} onClick={(e) => e.stopPropagation()} className="font-medium whitespace-nowrap text-slate-200 hover:text-white">
                        {f.project_name}
                      </Link>
                    </td>
                  )}
                  <td className="td">
                    <div className="font-mono text-xs text-slate-200">{f.package.name}</div>
                    <div className="font-mono text-[11px] text-slate-500">
                      {f.package.ecosystem} · {f.package.version}
                    </div>
                  </td>
                  <td className="td">
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={f.severity} cvss={f.cvss} />
                      {f.kev && <KevBadge />}
                      {f.kind && f.kind !== 'vulnerability' && <Pill tone={f.kind === 'malware' ? 'rose' : 'amber'}>{f.kind}</Pill>}
                    </div>
                  </td>
                  <td className="td">
                    <Pill tone={f.source === 'verified-sbom' ? 'emerald' : f.source === 'govulncheck' ? 'cyan' : 'slate'} title={f.source === 'verified-sbom' ? 'Declared in an SBOM submitted to PG Atlas' : f.source === 'govulncheck' ? 'Detected by govulncheck from the repo’s resolved modules — not present in PG Atlas edges' : 'Inferred from PG Atlas registry crawl'}>
                      {f.source === 'verified-sbom' ? 'PG Atlas SBOM' : f.source === 'govulncheck' ? 'govulncheck' : 'PG Atlas inferred'}
                    </Pill>
                  </td>
                  <td className="td">
                    <div className="flex flex-col items-start gap-1">
                      <ConfidencePill confidence={f.confidence} />
                      <ReachabilityPill reachability={f.reachability} trace={f.reachability_trace} />
                    </div>
                  </td>
                  <td className="td font-mono text-xs">{f.fixed_versions[0] ? <span className="text-emerald-300">{f.fixed_versions[0]}</span> : <span className="text-amber-300">none</span>}</td>
                  <td className="td">
                    <PriorityMeter value={f.priority} />
                  </td>
                </tr>
                {expandable && isOpen && (
                  <tr>
                    <td colSpan={showProject ? 9 : 8} className="p-0">
                      <Remediation f={f} />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
          </tbody>
        </table>
      </div>
    </>
  )
}
