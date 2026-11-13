/**
 * Runs the Semgrep SAST pass against the existing `public/data/snapshot.json`
 * without a full PG Atlas refresh — the same pass build-snapshot.ts runs, but
 * standalone so SAST coverage can be added/updated cheaply.
 *
 * Clones WG-listed repos (highest criticality first), runs
 * `semgrep scan --config <ruleset> --json`, and writes `sast_findings` onto each
 * project plus the `summary.sast` stats block. Results are cached per commit SHA.
 *
 * Usage: node scripts/annotate-sast.ts
 * Env:   SEMGREP=0 disables, SEMGREP_MAX_REPOS=<n> caps cloned repos,
 *        SEMGREP_REPOS=owner/name,... restricts targets,
 *        SEMGREP_CONFIG overrides the ruleset (default p/security-audit)
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { SastFinding, Snapshot } from '../src/api/types.ts'
import { CACHE_DIR, log } from './cache.ts'
import { ghKey, ghRepoOf } from './govulncheck.ts'
import { sastRepo, semgrepBinary, semgrepVersion, SEMGREP_CONFIG, SEMGREP_MAX, SEMGREP_REPOS } from './semgrep.ts'

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data/snapshot.json')

async function main() {
  const snap = JSON.parse(await readFile(OUT, 'utf8')) as Snapshot
  const targets = snap.projects
    .filter((p) => p.wg_listed)
    .flatMap((p) => p.repos.map((r) => ({ p, r, gh: ghRepoOf(r.repo_url) })))
    .filter((x): x is { p: (typeof snap.projects)[number]; r: (typeof snap.projects)[number]['repos'][number]; gh: { owner: string; name: string } } => !!x.gh && !!x.r.repo_url && (!SEMGREP_REPOS || SEMGREP_REPOS.includes(ghKey(x.gh))))
    .sort((a, b) => (b.r.criticality_score ?? 0) - (a.r.criticality_score ?? 0))
    .slice(0, SEMGREP_MAX)
  if (!targets.length) {
    log('no WG-listed GitHub repos in the snapshot — nothing to scan')
    return
  }
  const bin = await semgrepBinary()
  if (!bin) {
    log('semgrep: neither semgrep nor python3 found — aborting')
    process.exit(1)
  }
  const toolVersion = await semgrepVersion(bin)
  log(`semgrep ${toolVersion ?? ''}: scanning ${targets.length} WG-listed repos (${SEMGREP_CONFIG})${Number.isFinite(SEMGREP_MAX) ? ' (capped)' : ''}`)
  const byProject = new Map<string, SastFinding[]>()
  const sev = { error: 0, warning: 0, info: 0 }
  let scanned = 0
  for (const { p, r, gh } of targets) {
    const res = await sastRepo(bin, gh, r.repo_url!, { repo_id: r.canonical_id, repo_name: r.display_name, project_id: p.canonical_id, project_name: p.display_name })
    if (!res) continue
    scanned++
    for (const f of res.findings) {
      sev[f.severity]++
      const list = byProject.get(p.canonical_id) ?? []
      list.push(f)
      byProject.set(p.canonical_id, list)
    }
  }
  const targeted = new Set(targets.map((t) => t.p.canonical_id))
  const sevOrder = { error: 0, warning: 1, info: 2 }
  for (const p of snap.projects) {
    if (!targeted.has(p.canonical_id)) continue
    p.sast_findings = byProject.get(p.canonical_id) ?? []
    p.sast_findings.sort((a, b) => a.repo_id.localeCompare(b.repo_id) || sevOrder[a.severity] - sevOrder[b.severity])
  }
  snap.summary.sast = { ruleset: SEMGREP_CONFIG, tool_version: toolVersion, repos_targeted: targets.length, repos_scanned: scanned, findings: sev }
  if (scanned && !snap.summary.sources.includes('Semgrep')) snap.summary.sources.push('Semgrep')
  await mkdir(dirname(OUT), { recursive: true })
  await mkdir(CACHE_DIR, { recursive: true })
  await writeFile(OUT, JSON.stringify(snap))
  log(`wrote ${OUT} — ${scanned}/${targets.length} repos scanned · ${sev.error} errors / ${sev.warning} warnings / ${sev.info} info`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
