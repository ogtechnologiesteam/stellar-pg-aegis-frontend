import clsx from 'clsx'
import { useState } from 'react'
import { ChevronRight, ScanSearch } from 'lucide-react'
import type { Repo, SastFinding, SastSeverity } from '../api/types'
import { Card, CardHeader, Pill } from './ui'

const SEV_TONE: Record<SastSeverity, 'rose' | 'amber' | 'slate'> = { error: 'rose', warning: 'amber', info: 'slate' }
const SEV_ORDER: Record<SastSeverity, number> = { error: 0, warning: 1, info: 2 }

export function SastFindings({ findings, repos }: { findings: SastFinding[]; repos: Repo[] }) {
  const [open, setOpen] = useState<string | null>(null)
  const repoUrl = new Map(repos.map((r) => [r.canonical_id, r.repo_url]))
  const blob = (f: SastFinding) => {
    const u = repoUrl.get(f.repo_id)
    return u ? `${u}/blob/${f.commit_sha}/${f.path}#L${f.start_line}` : null
  }
  const counts: Record<SastSeverity, number> = { error: 0, warning: 0, info: 0 }
  for (const f of findings) counts[f.severity]++
  const byRepo = new Map<string, SastFinding[]>()
  for (const f of findings) byRepo.set(f.repo_name, [...(byRepo.get(f.repo_name) ?? []), f])
  const groups = [...byRepo.entries()]
  const grouped = groups.length > 1 && findings.length > 10

  const rows = (list: SastFinding[]) =>
    [...list]
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
      .map((f) => {
        const href = blob(f)
        const isOpen = open === f.id
        return (
          <li key={f.id}>
            <div className={clsx('cursor-pointer px-5 py-3 transition hover:bg-white/[0.02]', isOpen && 'bg-white/[0.03]')} onClick={() => setOpen(isOpen ? null : f.id)}>
              <div className="flex items-start gap-3">
                <Pill tone={SEV_TONE[f.severity]}>{f.severity}</Pill>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-xs text-slate-300" title={f.rule_id}>
                    {f.rule_id}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-slate-500" title={f.message}>
                    {f.message}
                  </div>
                </div>
                {href ? (
                  <a href={href} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className="shrink-0 font-mono text-[11px] text-indigo-300 hover:text-indigo-200">
                    {f.path}:{f.start_line}
                  </a>
                ) : (
                  <span className="shrink-0 font-mono text-[11px] text-slate-500">
                    {f.path}:{f.start_line}
                  </span>
                )}
                <ChevronRight className={clsx('mt-0.5 size-4 shrink-0 text-slate-500 transition', isOpen && 'rotate-90 text-slate-200')} />
              </div>
            </div>
            {isOpen && (
              <div className="border-t border-white/[0.04] bg-ink-950/40 px-5 py-4">
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs md:grid-cols-4">
                  <dt className="text-slate-500">Repository</dt>
                  <dd className="truncate font-mono text-slate-300">{f.repo_name}</dd>
                  <dt className="text-slate-500">Scanned commit</dt>
                  <dd className="font-mono text-slate-300">{f.commit_sha.slice(0, 10)}</dd>
                  {f.cwe.length > 0 && (
                    <>
                      <dt className="text-slate-500">CWE</dt>
                      <dd className="text-slate-300">{f.cwe.join(', ')}</dd>
                    </>
                  )}
                  {f.owasp.length > 0 && (
                    <>
                      <dt className="text-slate-500">OWASP</dt>
                      <dd className="text-slate-300">{f.owasp.join(', ')}</dd>
                    </>
                  )}
                </dl>
                <p className="mt-3 text-sm text-slate-300">{f.message}</p>
                {f.snippet && <pre className="mt-3 overflow-x-auto rounded-xl border border-white/[0.06] bg-ink-900 p-3 font-mono text-xs whitespace-pre text-slate-300">{f.snippet}</pre>}
              </div>
            )}
          </li>
        )
      })

  return (
    <Card className="mb-4">
      <CardHeader
        title="Static analysis"
        subtitle={`Semgrep security-audit rules — ${counts.error} errors · ${counts.warning} warnings · ${counts.info} info · not priority-scored`}
        icon={<ScanSearch className="size-4" />}
      />
      {grouped ? (
        groups.map(([repo, list]) => (
          <div key={repo}>
            <div className="border-b border-white/[0.05] bg-white/[0.02] px-5 py-2 font-mono text-xs text-slate-400">
              {repo} · {list.length}
            </div>
            <ul className="divide-y divide-white/[0.04]">{rows(list)}</ul>
          </div>
        ))
      ) : (
        <ul className="divide-y divide-white/[0.04]">{rows(findings)}</ul>
      )}
    </Card>
  )
}
