/**
 * Applies curated manual-review results to public/data/snapshot.json.
 *
 * Two jobs:
 *  1. Reachability verdicts from code review of cloned repos (traces prefixed "manual:"):
 *     - scout-audit git2: 'called' — remote.connect_auth exercised when linting untrusted repos
 *     - Soroban-Playground zod/UriTemplate/HTTP-transport GHSAs: 'not-called' — surfaces absent
 *     - rs-soroban-client tokio: 'not-called' — vulnerable modules feature-gated out
 *     - StellarAtlas + Grants-Gateway phantoms: 'unflagged' — dep/version absent from HEAD manifests
 *  2. Emit findings verified by manifest probe (composer.lock at HEAD) that PG Atlas
 *     never saw — currently stellarchain/v4-api (16 vulnerable locked packages).
 *
 * Idempotent: existing findings match by repo+vuln; emitted findings dedupe by id.
 */
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Finding, Reachability, SeverityCounts, Snapshot } from '../src/api/types.ts'
import { computePriority, logNorm } from '../src/lib/priority.ts'
import { log } from './cache.ts'
import { affectedFor, fetchOsv, kindOf, severityOf, UPGRADE_HINT } from './osv.ts'

const DIR = dirname(fileURLToPath(import.meta.url))
const OUT = resolve(DIR, '../public/data/snapshot.json')
// Manifest probes: repos whose real lockfiles exist but were never crawled into edges.
const PROBES = [
  { repo: 'pkg:github/stellarchain/v4-api', lock: '.cache/clones/v4-api/composer.lock', kind: 'composer' },
  { repo: 'pkg:github/Inferara/soroban-security-portal', lock: '.cache/clones/soroban-security-portal/UI/package-lock.json', kind: 'npm-lock' },
  { repo: 'pkg:github/rumblefishdev/soroban-block-explorer', lock: '.cache/clones/soroban-block-explorer/Cargo.lock', kind: 'cargo' },
  { repo: 'pkg:github/rumblefishdev/soroban-block-explorer', lock: '.cache/clones/soroban-block-explorer/pnpm-lock.yaml', kind: 'pnpm' },
  { repo: 'pkg:github/withObsrvr/stellarbeat', lock: '.cache/clones/stellarbeat/pnpm-lock.yaml', kind: 'pnpm' },
  { repo: 'pkg:github/withObsrvr/stellarbeat', lock: '.cache/clones/stellarbeat/python-fbas-service/requirements.txt', kind: 'reqs' },
  { repo: 'pkg:github/StellarCN/py-stellar-base', lock: '.cache/clones/py-stellar-base/uv.lock', kind: 'uv' },
  { repo: 'pkg:github/LedgerHQ/app-stellar', lock: '.cache/clones/app-stellar/Cargo.lock', kind: 'cargo' },
  { repo: 'pkg:github/Stellar-Light/stellarlight', lock: '.cache/clones/stellarlight/pnpm-lock.yaml', kind: 'pnpm' },
  { repo: 'pkg:github/Consulting-Manao/tansu', lock: '.cache/clones/tansu/Cargo.lock', kind: 'cargo' },
  { repo: 'pkg:github/Consulting-Manao/tansu', lock: '.cache/clones/tansu/dapp/bun.lock', kind: 'bun' },
  { repo: 'pkg:github/Consulting-Manao/tansu', lock: '.cache/clones/tansu/dapp/workers/ipfs-delegation/bun.lock', kind: 'bun' },
  { repo: 'pkg:github/Consulting-Manao/tansu', lock: '.cache/clones/tansu/website/bun.lock', kind: 'bun' },
  { repo: 'pkg:github/Inferara/soroban-ret', lock: '.cache/clones/soroban-ret/Cargo.lock', kind: 'cargo' },
] as const

// ---- 1. Manual verdicts ------------------------------------------------------
type Verdict = { v: Reachability; t: string }
const SOROPG_VERDICTS: Record<string, string> = {
  'GHSA-8r9q-7v3j-jr4g': 'manual: no resource templates registered — UriTemplate path unused',
  'GHSA-46jr-4wx8-v453': 'manual: StdioServerTransport only — HTTP request surface absent',
  'GHSA-mrhx-c7xc-m3w5': 'manual: no z.array schemas — vulnerable $ZodArray path unused',
}
const VERDICTS: Record<string, (f: Finding) => Verdict | null> = {
  'scout-audit': (f) =>
    f.package.name === 'git2'
      ? { v: 'called', t: 'manual: git2::connect_auth exercised when fetching untrusted repos for linting' }
      : null,
  'Soroban-Playground': (f) => {
    const t = SOROPG_VERDICTS[f.vuln_id]
    return t ? { v: 'not-called', t } : null
  },
  'rs-soroban-client': () => ({ v: 'not-called', t: 'manual: vulnerable tokio modules feature-gated out (features=["time"])' }),
  StellarAtlas: () => ({ v: 'unflagged', t: 'manual: package absent from all manifests at HEAD — stale PG Atlas edge' }),
  'Grants-Gateway-API': (f) =>
    ['morgan', 'joi', 'compression'].includes(f.package.name) || (f.package.name === 'express' && f.package.version === '4.14.0') || (f.package.name === 'body-parser' && f.package.version === '1.15.2')
      ? { v: 'unflagged', t: 'manual: version absent from pnpm-lock.yaml at HEAD — phantom edge' }
      : null,
  'stellar-php-sdk': (f) =>
    f.package.ecosystem === 'RubyGems' || f.package.ecosystem === 'crates.io'
      ? { v: 'not-called', t: 'manual: dev-tool/test-fixture manifest (tools/xdr-generator Gemfile.lock, tools/p28-owner-fixture Cargo.lock) — not shipped SDK surface' }
      : null,
}

// ---- 2. Manifest probe → emit findings ---------------------------------------
type Pkg = { name: string; version: string; eco: string }
// TOML [[package]] locks (Cargo.lock, uv.lock) — name line followed by version line.
function tomlPkgs(txt: string, eco: string): Pkg[] {
  const out: Pkg[] = []
  let name: string | null = null
  for (const l of txt.split('\n')) {
    const n = /^name = "(.+)"/.exec(l)
    const v = /^version = "(.+)"/.exec(l)
    if (n) name = n[1]
    if (v && name) {
      out.push({ name, version: v[1], eco })
      name = null
    }
  }
  return out
}
// pnpm v9: resolved pins live in the trailing `snapshots:` map ("name@ver" keys).
function pnpmPkgs(txt: string): Pkg[] {
  const i = txt.search(/^snapshots:/m)
  if (i < 0) return []
  const out = new Map<string, Pkg>()
  for (const l of txt.slice(i).split('\n')) {
    const k = /^ {2}'?([^' ]+?)'?:/.exec(l)
    if (!k) continue
    const at = k[1].lastIndexOf('@')
    if (at < 1) continue
    const version = k[1].slice(at + 1).split('(')[0].trim()
    if (!/^\d/.test(version)) continue
    out.set(k[1], { name: k[1].slice(0, at), version, eco: 'npm' })
  }
  return [...out.values()].filter((d) => d.name && !d.name.startsWith('@types'))
}
// bun.lock (v2): JSONC-ish "packages" map, keys "name": ["name@version", ...].
// Parsed per-line — full JSON.parse chokes on bun's inline strings.
function bunPkgs(txt: string): Pkg[] {
  const out = new Map<string, Pkg>()
  for (const l of txt.split('\n')) {
    const m = /^\s{4}"((?:@[^/"]+\/)?[^"@]+)": \[\s*"(?:npm:)?(?:@[^@"]+\/)?[^@"]+@(\d[^"]*)"/.exec(l)
    if (!m || !/^\d/.test(m[2])) continue
    out.set(`${m[1]}@${m[2]}`, { name: m[1], version: m[2], eco: 'npm' })
  }
  return [...out.values()].filter((d) => d.name && !d.name.startsWith('@types'))
}
async function probePkgs(probe: (typeof PROBES)[number]): Promise<Pkg[]> {
  const txt = await readFile(resolve(DIR, probe.lock), 'utf8')
  if (probe.kind === 'cargo') return tomlPkgs(txt, 'crates.io')
  if (probe.kind === 'uv') return tomlPkgs(txt, 'PyPI')
  if (probe.kind === 'pnpm') return pnpmPkgs(txt)
  if (probe.kind === 'bun') return bunPkgs(txt)
  if (probe.kind === 'reqs')
    return txt
      .split('\n')
      .map((l) => /^([A-Za-z0-9_.-]+)==([0-9][^;\s]*)/.exec(l.trim()))
      .filter((m): m is RegExpExecArray => !!m)
      .map((m) => ({ name: m[1], version: m[2], eco: 'PyPI' }))
  const lock = JSON.parse(txt) as { packages: unknown }
  if (probe.kind === 'composer') return (lock.packages as { name: string; version: string }[]).map((p) => ({ name: p.name, version: p.version.replace(/^v/, ''), eco: 'Packagist' }))
  // npm package-lock: { packages: { "node_modules/x": { version } } }
  return Object.entries(lock.packages as Record<string, { version?: string }>)
    .filter(([k]) => k)
    .map(([k, v]) => ({ name: k.split('node_modules/').pop()!, version: v.version ?? '0', eco: 'npm' }))
    .filter((d) => d.name && !d.name.startsWith('@types'))
}

async function emitManifestFindings(snap: Snapshot): Promise<number> {
  const vulnById = new Map(snap.vulns.map((v) => [v.id, v]))
  const maxCrit = Math.max(0, ...snap.projects.flatMap((p) => p.repos.map((r) => r.criticality_score ?? 0)))
  let emitted = 0
  for (const probe of PROBES) {
    const proj = snap.projects.find((p) => p.repos.some((r) => r.canonical_id === probe.repo))
    const repo = proj?.repos.find((r) => r.canonical_id === probe.repo)
    if (!proj || !repo) continue
    let pkgs: Pkg[] = []
    try {
      pkgs = await probePkgs(probe)
    } catch {
      log(`manifest probe: ${probe.repo} — lockfile missing, skipped`)
      continue
    }
    // Dedupe by vuln+repo (edge findings carry source-specific ids) and by emitted id.
    const seenPair = new Set(proj.findings.map((f) => `${f.vuln_id}|${f.repo_id}`))
    const existing = new Set(proj.findings.map((f) => f.id))
    for (let i = 0; i < pkgs.length; i += 100) {
      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        body: JSON.stringify({ queries: pkgs.slice(i, i + 100).map((d) => ({ package: { name: d.name, ecosystem: d.eco }, version: d.version })) }),
      }).then((r) => r.json() as Promise<{ results: { vulns?: { id: string }[] }[] }>)
      for (let j = 0; j < res.results.length; j++) {
        for (const hit of res.results[j]?.vulns ?? []) {
          const o = await fetchOsv(hit.id)
          if (!o || o.withdrawn) continue
          const id = `${o.id}|${repo.canonical_id}|manifest`
          if (existing.has(id) || seenPair.has(`${o.id}|${repo.canonical_id}`)) continue
          let { severity, cvss } = severityOf(o)
          if (severity === 'unknown') {
            const ghsa = await fetchOsv(o.aliases?.find((a) => a.startsWith('GHSA-')) ?? '')
            if (ghsa) ({ severity, cvss } = severityOf(ghsa))
          }
          const d = pkgs[i + j]
          const { fixed, range } = affectedFor(o, d.eco, d.name)
          const { priority, breakdown } = computePriority({ severity, cvss, criticality: logNorm(repo.criticality_score, maxCrit), kev: false, epss: null, reach: logNorm(repo.criticality_score, maxCrit), fixAvailable: fixed.length > 0, confidence: 'confirmed' })
          proj.findings.push({
            id,
            repo_id: repo.canonical_id,
            repo_name: repo.display_name,
            project_id: proj.canonical_id,
            project_name: proj.display_name,
            vuln_id: o.id,
            summary: o.summary || o.details?.split('\n')[0]?.slice(0, 160) || o.id,
            package: { purl: `pkg:${({ npm: 'npm', Packagist: 'composer', 'crates.io': 'cargo', PyPI: 'pypi' }) as Record<string, string>}[d.eco] ?? d.eco.toLowerCase()}/${d.name}@${d.version}`, name: d.name, ecosystem: d.eco, version: d.version, version_range: d.version, resolution: 'exact' },
            severity,
            cvss,
            kind: kindOf(o),
            kev: false,
            epss: null,
            confidence: 'confirmed',
            source: 'verified-sbom',
            reachability: null,
            reachability_trace: 'manual: verified present in lockfile at HEAD — PG Atlas edge missing',
            status: 'open',
            fixed_versions: fixed,
            upgrade_hint: fixed[0] ? (UPGRADE_HINT[d.eco]?.(d.name, fixed[0]) ?? null) : null,
            advisory_published: o.published ?? null,
            priority,
            priority_breakdown: breakdown,
          })
          existing.add(id)
          emitted++
          if (!vulnById.has(o.id)) {
            const v = {
              id: o.id, aliases: o.aliases ?? [], summary: o.summary || o.details?.split('\n')[0]?.slice(0, 160) || o.id, details: (o.details ?? '').slice(0, 1500), severity, cvss, cvss_vector: null, kind: kindOf(o),
              published: o.published ?? null, modified: o.modified ?? null, kev: false, epss: null, ecosystem: d.eco, package: d.name, affected_range: range,
              fixed_versions: fixed, references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${o.id}` }, ...(o.references ?? []).slice(0, 8)],
              exposed_projects: 1, exposed_repos: 1,
            }
            snap.vulns.push(v)
            vulnById.set(o.id, v)
          }
          ;(snap.exposures[o.id] ??= []).push({ repo_id: repo.canonical_id, repo_name: repo.display_name, project_id: proj.canonical_id, project_name: proj.display_name, depth: 1, via: null, criticality_score: repo.criticality_score, confidence: 'confirmed' })
        }
      }
    }
    log(`manifest probe: ${probe.repo} — ${pkgs.length} locked packages scanned`)
  }

  // Backfill advisory kinds for vulns emitted before kind tracking — RustSec
  // is the only source with non-vuln categories in our data, so only RUSTSEC
  // ids need a lookup (disk-cached); everything else is a real vuln.
  const missing = snap.vulns.filter((v) => !v.kind)
  for (let i = 0; i < missing.length; i += 20) {
    await Promise.all(
      missing.slice(i, i + 20).map(async (v) => {
        if (v.id.startsWith('MAL-')) v.kind = 'malware'
        else if (v.id.startsWith('RUSTSEC-')) v.kind = kindOf((await fetchOsv(v.id)) ?? { id: v.id })
        else v.kind = 'vulnerability'
      }),
    )
  }
  if (missing.length) log(`advisory kinds classified for ${missing.length} vulns`)
  for (const p of snap.projects) for (const f of p.findings) if (!f.kind) f.kind = vulnById.get(f.vuln_id)?.kind ?? 'vulnerability'
  return emitted
}

async function main() {
  const snap = JSON.parse(await readFile(OUT, 'utf8')) as Snapshot

  let marked = 0
  for (const p of snap.projects) {
    for (const f of p.findings) {
      const v = VERDICTS[f.repo_name]?.(f)
      if (v && f.reachability !== v.v) {
        f.reachability = v.v
        f.reachability_trace = v.t
        marked++
      }
    }
  }
  log(`manual verdicts applied to ${marked} findings`)

  const emitted = await emitManifestFindings(snap)
  log(`manifest probe: emitted ${emitted} findings`)

  // Recount aggregates (same as annotate-reachability).
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
  snap.summary.reachability = reach.called + reach['not-called'] + reach.unflagged ? reach : null
  await writeFile(OUT, JSON.stringify(snap))
  log(`wrote ${OUT} — called: ${reach.called}, not-called: ${reach['not-called']}, unflagged: ${reach.unflagged}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
