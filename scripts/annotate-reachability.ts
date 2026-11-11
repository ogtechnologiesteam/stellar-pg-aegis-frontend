/**
 * Annotates `public/data/snapshot.json` in place with govulncheck reachability —
 * the same pass build-snapshot.ts runs during a full refresh, but standalone so
 * reachability can be added/updated without re-crawling PG Atlas.
 *
 * Clones repos that have Go findings (most findings first), runs
 * `govulncheck -json ./...` per go.mod, and sets `reachability` /
 * `reachability_trace` on each Go finding. Verdicts are cached per commit SHA.
 *
 * Usage: node scripts/annotate-reachability.ts
 * Env:   GOVC=0 disables, GOVC_MAX_REPOS=<n> caps cloned repos (default: all)
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Finding, Reachability, SeverityCounts, Snapshot } from '../src/api/types.ts'
import { computePriority, logNorm } from '../src/lib/priority.ts'
import { CACHE_DIR, log } from './cache.ts'
import { affectedFor, fetchOsv, severityOf, UPGRADE_HINT, type OsvVuln } from './osv.ts'
import { ghKey, ghRepoOf, govcBinary, govcRepo, GOVC_MAX, GOVC_REPOS, type ReachVerdicts } from './govulncheck.ts'

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data/snapshot.json')

async function main() {
  const snap = JSON.parse(await readFile(OUT, 'utf8')) as Snapshot
  const repoUrl = new Map<string, string | null>()
  const goCount = new Map<string, number>()
  for (const p of snap.projects) {
    for (const r of p.repos) repoUrl.set(r.canonical_id, r.repo_url)
    for (const f of p.findings) {
      if (f.package.ecosystem !== 'Go') continue
      goCount.set(f.repo_id, (goCount.get(f.repo_id) ?? 0) + 1)
    }
  }
  const targets = [...goCount.entries()]
    .map(([id, n]) => ({ id, n, gh: ghRepoOf(repoUrl.get(id) ?? null) }))
    .filter((x): x is { id: string; n: number; gh: { owner: string; name: string } } => !!x.gh && !!repoUrl.get(x.id) && (!GOVC_REPOS || GOVC_REPOS.includes(ghKey(x.gh))))
    .sort((a, b) => b.n - a.n)
    .slice(0, GOVC_MAX)
  if (!targets.length) {
    log('no Go findings in the snapshot — nothing to annotate')
    return
  }
  const bin = await govcBinary()
  if (!bin) {
    log('govulncheck: neither govulncheck nor go found — aborting')
    process.exit(1)
  }
  log(`govulncheck: annotating ${targets.length}/${goCount.size} repos with Go findings${Number.isFinite(GOVC_MAX) ? ' (capped)' : ''}`)
  const results = new Map<string, ReachVerdicts | null>()
  for (const { id, gh } of targets) {
    results.set(id, await govcRepo(bin, gh, repoUrl.get(id)!))
  }
  const counts = { called: 0, 'not-called': 0, unflagged: 0 }
  const vulnById = new Map(snap.vulns.map((v) => [v.id, v]))
  for (const p of snap.projects) {
    for (const f of p.findings) {
      if (f.package.ecosystem !== 'Go') continue
      const per = results.get(f.repo_id)
      if (per === undefined) continue // capped out — leave as-is
      // govulncheck reports canonical GO- ids; the finding may key on a GHSA alias.
      const hits = [f.vuln_id, ...(vulnById.get(f.vuln_id)?.aliases ?? [])].map((c) => per?.get(c)).filter((x): x is { v: Reachability; t: string | null; m: string | null; v2: string | null } => !!x)
      const hit = hits.find((h) => h.v === 'called') ?? hits[0]
      f.reachability = per === null ? null : (hit?.v ?? 'unflagged')
      f.reachability_trace = per === null ? null : (hit?.t ?? null)
      if (f.reachability) counts[f.reachability]++
    }
  }
  if (results.size && !snap.summary.sources.includes('govulncheck')) snap.summary.sources.push('govulncheck')

  // Emit new findings for advisories govulncheck reports but edge matching missed —
  // versions come from the repo's own resolved go.mod (strongest version evidence).
  const repoMeta = new Map<string, { p: (typeof snap.projects)[number]; r: (typeof snap.projects)[number]['repos'][number] }>()
  for (const p of snap.projects) for (const r of p.repos) repoMeta.set(r.canonical_id, { p, r })
  const maxCrit = Math.max(0, ...[...repoMeta.values()].map(({ r }) => r.criticality_score ?? 0))
  const pend: { vid: string; rm: { p: (typeof snap.projects)[number]; r: (typeof snap.projects)[number]['repos'][number] }; g: { v: Reachability; t: string | null; m: string | null; v2: string | null } }[] = []
  const toFetch = new Set<string>()
  for (const [repoId, per] of results) {
    if (!per) continue
    const rm = repoMeta.get(repoId)
    if (!rm) continue
    const matched = new Set(rm.p.findings.filter((f) => f.repo_id === repoId).flatMap((f) => [f.vuln_id, ...(vulnById.get(f.vuln_id)?.aliases ?? [])]))
    for (const [vid, g] of per) {
      if (matched.has(vid) || !g.m || !g.v2) continue
      pend.push({ vid, rm, g })
      toFetch.add(vid)
    }
  }
  let emitted = 0
  if (toFetch.size) {
    log(`govulncheck: ${toFetch.size} advisories reported that edge matching missed`)
    const newOsv = new Map<string, OsvVuln>()
    await Promise.all([...toFetch].map(async (id) => { const v = await fetchOsv(id); if (v && !v.withdrawn) newOsv.set(id, v) }))
    const kev = new Set<string>(await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json').then((r) => r.json()).then((d) => ((d as { vulnerabilities?: { cveID: string }[] }).vulnerabilities ?? []).map((v) => v.cveID)).catch(() => []))
    for (const { vid, rm, g } of pend) {
      const o = newOsv.get(vid)
      if (!o) continue
      const ids = [o.id, ...(o.aliases ?? [])].filter((a) => a.startsWith('CVE-'))
      let { severity, cvss } = severityOf(o)
      if (severity === 'unknown') {
        const ghsa = await fetchOsv(o.aliases?.find((a) => a.startsWith('GHSA-')) ?? '')
        if (ghsa) ({ severity, cvss } = severityOf(ghsa))
      }
      const { fixed, range } = affectedFor(o, 'Go', g.m!)
      const { priority, breakdown } = computePriority({ severity, cvss, criticality: logNorm(rm.r.criticality_score, maxCrit), kev: ids.some((c) => kev.has(c)), epss: null, reach: logNorm(rm.r.criticality_score, maxCrit), fixAvailable: fixed.length > 0, confidence: 'confirmed' })
      const f: Finding = {
        id: `${vid}|${rm.r.canonical_id}|govulncheck`,
        repo_id: rm.r.canonical_id,
        repo_name: rm.r.display_name,
        project_id: rm.p.canonical_id,
        project_name: rm.p.display_name,
        vuln_id: vid,
        summary: o.summary || o.details?.split('\n')[0]?.slice(0, 160) || vid,
        package: { purl: `pkg:golang/${g.m}@${g.v2}`, name: g.m!, ecosystem: 'Go', version: g.v2!, version_range: g.v2!, resolution: 'exact' },
        severity,
        cvss,
        kev: ids.some((c) => kev.has(c)),
        epss: null,
        confidence: 'confirmed',
        source: 'govulncheck',
        reachability: g.v,
        reachability_trace: g.t,
        status: 'open',
        fixed_versions: fixed,
        upgrade_hint: fixed[0] ? (UPGRADE_HINT.Go?.(g.m!, fixed[0]) ?? null) : null,
        advisory_published: o.published ?? null,
        priority,
        priority_breakdown: breakdown,
      }
      rm.p.findings.push(f)
      emitted++
      if (!vulnById.has(vid)) {
        const v = {
          id: o.id, aliases: o.aliases ?? [], summary: f.summary, details: (o.details ?? '').slice(0, 1500), severity, cvss, cvss_vector: null,
          published: o.published ?? null, modified: o.modified ?? null, kev: f.kev, epss: null, ecosystem: 'Go' as const, package: g.m!, affected_range: range,
          fixed_versions: fixed, references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${o.id}` }, ...(o.references ?? []).slice(0, 8)],
          exposed_projects: 1, exposed_repos: 1,
        }
        snap.vulns.push(v)
        vulnById.set(vid, v)
      }
      ;(snap.exposures[vid] ??= []).push({ repo_id: rm.r.canonical_id, repo_name: rm.r.display_name, project_id: rm.p.canonical_id, project_name: rm.p.display_name, depth: 1, via: null, criticality_score: rm.r.criticality_score, confidence: 'confirmed' })
    }
    log(`govulncheck: emitted ${emitted} new findings`)
  }

  // Recount aggregates after annotation + emission.
  const empty = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 })
  const open = empty()
  const reach: Record<Reachability, number> = { called: 0, 'not-called': 0, unflagged: 0 }
  const eco = new Map<string, { findings: number; repos: Set<string> }>()
  const ages: number[] = []
  for (const p of snap.projects) {
    p.findings.sort((a, b) => b.priority - a.priority)
    const pc = empty()
    for (const f of p.findings) {
      pc[f.severity]++
      open[f.severity]++
      if (f.reachability) reach[f.reachability]++
      const e = eco.get(f.package.ecosystem) ?? { findings: 0, repos: new Set<string>() }
      e.findings++
      e.repos.add(f.repo_id)
      eco.set(f.package.ecosystem, e)
      if (f.fixed_versions.length && f.advisory_published) ages.push((Date.now() - Date.parse(f.advisory_published)) / 86_400_000)
    }
    p.open_findings = pc
    p.max_priority = p.findings[0]?.priority ?? 0
    for (const r of p.repos) r.open_findings = p.findings.filter((f) => f.repo_id === r.canonical_id).length
  }
  ages.sort((a, b) => a - b)
  snap.summary.open_findings = open
  snap.summary.affected_projects = new Set(snap.projects.flatMap((p) => p.findings.map((f) => f.project_id))).size
  snap.summary.kev_findings = snap.projects.flatMap((p) => p.findings).filter((f) => f.kev).length
  snap.summary.fixable_findings = snap.projects.flatMap((p) => p.findings).filter((f) => f.fixed_versions.length > 0).length
  snap.summary.by_ecosystem = [...eco.entries()].map(([ecosystem, v]) => ({ ecosystem, findings: v.findings, repos: v.repos.size })).sort((a, b) => b.findings - a.findings)
  snap.summary.median_fixable_advisory_age_days = ages.length ? Math.round(ages[ages.length >> 1]) : null
  snap.summary.reachability = results.size || reach.called + reach['not-called'] + reach.unflagged ? reach : null
  await mkdir(dirname(OUT), { recursive: true })
  await mkdir(CACHE_DIR, { recursive: true })
  await writeFile(OUT, JSON.stringify(snap))
  log(`wrote ${OUT} — called: ${counts.called}, not-called: ${counts['not-called']}, unflagged: ${counts.unflagged}, emitted: ${emitted} (${[...results.values()].filter(Boolean).length}/${targets.length} repos analyzed)`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
