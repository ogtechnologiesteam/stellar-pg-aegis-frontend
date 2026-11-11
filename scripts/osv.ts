// Shared OSV advisory helpers — CVSS v3 scoring, severity labels, affected-range
// extraction and upgrade hints. Used by build-snapshot.ts and annotate-reachability.ts.
import type { AdvisoryKind, Severity } from '../src/api/types.ts'
import { cacheGet, cacheSet } from './cache.ts'

const OSV_TTL_MS = 30 * 24 * 3600_000

export const UPGRADE_HINT: Record<string, (p: string, v: string) => string> = {
  npm: (p, v) => `npm install ${p}@${v}`,
  'crates.io': (p, v) => `cargo update -p ${p} --precise ${v}`,
  PyPI: (p, v) => `pip install '${p}>=${v}'`,
  Maven: (p, v) => `Set ${p} to ${v} in build.gradle / pom.xml`,
  Go: (p, v) => `go get ${p}@${v.startsWith('v') ? v : `v${v}`}`,
  Pub: (p, v) => `dart pub upgrade ${p}  # constraint ^${v}`,
  Packagist: (p, v) => `composer require ${p}:^${v}`,
  NuGet: (p, v) => `dotnet add package ${p} --version ${v}`,
  RubyGems: (p, v) => `bundle update ${p}  # >= ${v}`,
  'GitHub Actions': (p, v) => `uses: ${p}@v${v.replace(/^v/, '')}`,
}

function cvss3(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')))
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  } as const
  const changed = m.S === 'C'
  const pr = ({ N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 } as Record<string, number>)[m.PR]
  const av = (W.AV as Record<string, number>)[m.AV]
  const ac = (W.AC as Record<string, number>)[m.AC]
  const ui = (W.UI as Record<string, number>)[m.UI]
  const [c, i, a] = [m.C, m.I, m.A].map((x) => (W.CIA as Record<string, number>)[x])
  if ([pr, av, ac, ui, c, i, a].some((x) => x === undefined)) return null
  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  if (impact <= 0) return 0
  const exploit = 8.22 * av * ac * pr * ui
  const roundUp = (x: number) => Math.ceil(x * 10 - 1e-9) / 10
  return roundUp(Math.min(changed ? 1.08 * (impact + exploit) : impact + exploit, 10))
}

const labelFromScore = (s: number): Severity => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'unknown')
export const LABEL: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }

export interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
}
export interface OsvVuln {
  id: string
  summary?: string
  details?: string
  aliases?: string[]
  published?: string
  modified?: string
  withdrawn?: string
  severity?: { type: string; score: string }[]
  database_specific?: { severity?: string }
  affected?: { package?: { name: string; ecosystem: string }; ranges?: { type: string; events: OsvEvent[] }[]; versions?: string[]; database_specific?: { severity?: string; categories?: string[]; informational?: string }; ecosystem_specific?: { severity?: string } }[]
  references?: { type: string; url: string }[]
}

export function affectedFor(v: OsvVuln, ecosystem: string, name: string) {
  const entries = (v.affected ?? []).filter((a) => a.package?.ecosystem === ecosystem && a.package.name.toLowerCase() === name.toLowerCase())
  const fixed = new Set<string>()
  const ranges: string[] = []
  for (const a of entries) {
    for (const r of a.ranges ?? []) {
      if (r.type === 'GIT') continue
      let lo: string | undefined
      for (const e of r.events) {
        if (e.introduced !== undefined) lo = e.introduced
        if (e.fixed !== undefined || e.last_affected !== undefined) {
          if (e.fixed) fixed.add(e.fixed)
          const hi = e.fixed ? `<${e.fixed}` : `<=${e.last_affected}`
          ranges.push(lo && lo !== '0' ? `>=${lo} ${hi}` : hi)
          lo = undefined
        }
      }
      if (lo !== undefined) ranges.push(lo === '0' ? 'all versions' : `>=${lo}`)
    }
    if (!a.ranges?.length && a.versions?.length) ranges.push(`${a.versions.length} listed versions`)
  }
  return { fixed: [...fixed], range: ranges.join(' || ') || 'see advisory' }
}

export function severityOf(v: OsvVuln): { severity: Severity; cvss: number | null; vector: string | null } {
  const vector = v.severity?.find((s) => s.type === 'CVSS_V3')?.score ?? v.severity?.[0]?.score ?? null
  const score = vector ? cvss3(vector) : null
  const label = v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity || a.ecosystem_specific?.severity)?.database_specific?.severity
  const severity = (label && LABEL[label.toUpperCase()]) || (score != null ? labelFromScore(score) : 'unknown')
  return { severity, cvss: score, vector }
}

// Advisory class from ecosystem metadata — RustSec records carry categories /
// informational markers in affected[].database_specific (e.g. paste = unmaintained).
// MAL-* ids come from the malicious-packages DB. Everything else is a real vuln.
const KINDS = new Set<AdvisoryKind>(['vulnerability', 'unmaintained', 'unsound', 'notice', 'yanked', 'malware'])
export function kindOf(v: OsvVuln): AdvisoryKind {
  if (v.id.startsWith('MAL-')) return 'malware'
  let fallback: AdvisoryKind = 'vulnerability'
  for (const a of v.affected ?? []) {
    for (const c of a.database_specific?.categories ?? []) if (KINDS.has(c as AdvisoryKind) && c !== 'vulnerability') return c as AdvisoryKind
    const i = a.database_specific?.informational
    if (i && KINDS.has(i as AdvisoryKind) && i !== 'vulnerability') fallback = i as AdvisoryKind
  }
  return fallback
}

// Fetches one OSV record by id (null on 404/network failure). Disk-cached 30d.
export async function fetchOsv(id: string): Promise<OsvVuln | null> {
  const hit = await cacheGet<OsvVuln | null>(`osv:${id}`, OSV_TTL_MS)
  if (hit !== undefined) return hit
  let out: OsvVuln | null = null
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(30_000) })
    if (res.ok) out = (await res.json()) as OsvVuln
  } catch {
    /* network failure */
  }
  await cacheSet(`osv:${id}`, out)
  return out
}
