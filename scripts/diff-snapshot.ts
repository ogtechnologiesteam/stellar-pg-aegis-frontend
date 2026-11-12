/**
 * Diffs two snapshot.json files and prints a markdown report for GitHub Actions
 * ($GITHUB_STEP_SUMMARY). Used by the snapshot-refresh workflow to flag newly
 * appeared / resolved findings between refreshes.
 *
 * Usage: node scripts/diff-snapshot.ts <old.json> <new.json>
 * Also appends new_findings=N, resolved_findings=N, kev_new=N to $GITHUB_OUTPUT when set.
 */
import { appendFile, readFile } from 'node:fs/promises'
import type { Finding, Snapshot } from '../src/api/types.ts'

const [oldPath, newPath] = process.argv.slice(2)
if (!oldPath || !newPath) {
  console.error('usage: diff-snapshot.ts <old.json> <new.json>')
  process.exit(2)
}
const prev = JSON.parse(await readFile(oldPath, 'utf8')) as Snapshot
const next = JSON.parse(await readFile(newPath, 'utf8')) as Snapshot

const findingsOf = (s: Snapshot) => s.projects.flatMap((p) => p.findings)
const byId = (fs: Finding[]) => new Map(fs.map((f) => [f.id, f]))
const before = byId(findingsOf(prev))
const after = byId(findingsOf(next))

const added = [...after.values()].filter((f) => !before.has(f.id)).sort((a, b) => b.priority - a.priority)
const removed = [...before.values()].filter((f) => !after.has(f.id))
const kevNew = added.filter((f) => f.kev).length + [...after.values()].filter((f) => f.kev && before.has(f.id) && !before.get(f.id)!.kev).length
const reachFlips = [...after.values()].filter((f) => before.has(f.id) && before.get(f.id)!.reachability !== f.reachability)
const newVulnIds = new Set(next.vulns.map((v) => v.id))
const addedAdvisories = prev.vulns.filter((v) => !newVulnIds.has(v.id)).length
const newProjects = new Set(added.map((f) => f.project_id))

const sev = (f: Finding) => (f.kev ? `${f.severity} (KEV)` : f.severity)
const esc = (s: string) => s.replace(/\|/g, '\\|')
const row = (f: Finding) =>
  `| ${f.project_name} | ${sev(f)} | ${esc(f.vuln_id)} | \`${esc(f.package.name)}@${esc(f.package.version)}\` | ${f.priority.toFixed(1)} | ${f.reachability ?? '—'} |`

const out: string[] = [
  `## Snapshot diff — ${next.summary.generated_at.slice(0, 10)}`,
  '',
  `**${added.length} new findings** · ${removed.length} resolved · ${kevNew} known-exploited · ${newProjects.size} projects newly affected`,
  '',
]
if (added.length) {
  out.push('| Project | Severity | Advisory | Package | Priority | Reachability |', '| --- | --- | --- | --- | --- | --- |', ...added.slice(0, 50).map(row))
  if (added.length > 50) out.push(`| … | | ${added.length - 50} more | | | |`)
  out.push('')
}
if (reachFlips.length) {
  out.push('### Reachability changes', '', '| Project | Advisory | Was → Now |', '| --- | --- | --- |')
  for (const f of reachFlips.slice(0, 20)) out.push(`| ${f.project_name} | ${esc(f.vuln_id)} | ${before.get(f.id)!.reachability ?? '—'} → ${f.reachability ?? '—'} |`)
  out.push('')
}
if (addedAdvisories) out.push(`_${addedAdvisories} tracked advisories no longer affect any public good._`, '')
if (!added.length && !removed.length && !reachFlips.length) out.push('_No finding changes since the last snapshot._')

console.log(out.join('\n'))

if (process.env.GITHUB_OUTPUT) {
  await appendFile(process.env.GITHUB_OUTPUT, `new_findings=${added.length}\nresolved_findings=${removed.length}\nkev_new=${kevNew}\n`)
}
