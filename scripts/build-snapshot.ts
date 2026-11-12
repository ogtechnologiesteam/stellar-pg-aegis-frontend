/**
 * Builds `public/data/snapshot.json` from real, public data sources. This is the stand-in for
 * the Aegis backend (Specification.md §8) until it exists.
 *
 *   PG Atlas API  → public-good projects, repos, dependency edges (SBOM + inferred), dependents
 *   OSV.dev       → vulnerabilities matched by PURL + version
 *   CISA KEV      → known-exploited flag
 *   FIRST EPSS    → exploitation probability
 *   GitHub        → SECURITY.md, private vulnerability reporting, published advisories,
 *                   Dependabot / Renovate config (requires GITHUB_TOKEN; skipped otherwise)
 *   Scorecard     → OpenSSF Scorecard overall score
 *   govulncheck   → Go call analysis: shallow-clones repos with Go findings and checks
 *                   whether their code calls the vulnerable symbols (reachability)
 *
 * Usage: GITHUB_TOKEN=... node scripts/build-snapshot.ts
 * Env:   PG_ATLAS_API (default: https://api.pgatlas.xyz), GITHUB_TOKEN, GH_MAX_REPOS,
 *        GOVC=0 disables call analysis, GOVC_MAX_REPOS caps cloned Go repos
 */
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  ActivityStatus,
  AuditReport,
  Confidence,
  DisclosureChannel,
  EcosystemSummary,
  EdgeSource,
  Exposure,
  Finding,
  Hygiene,
  PgAtlasMetadata,
  ProjectDetail,
  PublishedAdvisory,
  Reachability,
  Repo,
  Resolution,
  SeverityCounts,
  Snapshot,
  Vuln,
} from '../src/api/types.ts'
import { computePriority, logNorm } from '../src/lib/priority.ts'
import { affectedFor, fetchOsv, kindOf, LABEL, severityOf, UPGRADE_HINT, type OsvVuln } from './osv.ts'
import { CACHE_DIR, cacheGet, cachePath, cacheSet, log } from './cache.ts'
import { CLONES_DIR, ghKey, ghRepoOf, govcBinary, govcRepo, GOVC_MAX, GOVC_REPOS, type ReachVerdicts } from './govulncheck.ts'

const PG = (process.env.PG_ATLAS_API ?? 'https://api.pgatlas.xyz').replace(/\/$/, '')
const WG_SITE = 'https://scf-public-goods-maintenance.github.io'
const PORTAL = (process.env.SECURITY_PORTAL_API ?? 'https://stellarsecurityportal.com/api/v1').replace(/\/$/, '')
const PORTAL_SITE = new URL(PORTAL).origin
const GH_TOKEN = process.env.GITHUB_TOKEN ?? ''
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data/snapshot.json')
const NOW = new Date().toISOString()
const MAX_DEPTH = 3

// ---------------------------------------------------------------- helpers

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// PG Atlas allows 100 req/min per IP (docs: pg-atlas/security). Space requests to stay under it.
const PG_INTERVAL_MS = 60_000 / 90
let pgNextSlot = 0
async function pgThrottle() {
  const now = Date.now()
  const slot = Math.max(now, pgNextSlot)
  pgNextSlot = slot + PG_INTERVAL_MS
  if (slot > now) await sleep(slot - now)
}

// Disk cache (./cache.ts) so re-runs within CACHE_TTL reuse fetched responses (PG
// Atlas GETs and per-repo GitHub/Scorecard lookups). GitHub responses use their own
// TTL so enrichment stays fresh without re-crawling the graph.
const CACHE_TTL_MS = 24 * 3600_000
const GH_TTL_MS = 72 * 3600_000

async function http<T>(url: string, init: RequestInit = {}, { allow404 = false, retries = 3 } = {}): Promise<T | null> {
  const isPg = url.startsWith(PG)
  const cacheable = isPg && !init.method
  // Cache PG Atlas responses under the canonical host so PG_ATLAS_API mirrors
  // (e.g. the DigitalOcean app URL) reuse the same on-disk entries.
  const cacheKey = isPg ? url.replace(PG, 'https://api.pgatlas.xyz') : url
  if (cacheable) {
    const hit = await cacheGet<T | null>(cacheKey, CACHE_TTL_MS)
    if (hit !== undefined) return hit
  }
  for (let attempt = 0; ; attempt++) {
    try {
      if (isPg) await pgThrottle()
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(45_000) })
      if (res.status === 404 && allow404) {
        if (cacheable) await writeFile(cachePath(cacheKey), 'null')
        return null
      }
      if (res.ok) {
        const body = (await res.json()) as T
        if (cacheable) await writeFile(cachePath(cacheKey), JSON.stringify(body))
        return body
      }
      if (res.status === 429 && attempt < 8) {
        const wait = Number(res.headers.get('retry-after')) || 15
        log(`429 from ${new URL(url).host}, waiting ${wait}s`)
        await sleep(wait * 1000)
        continue
      }
      if (attempt < retries && res.status >= 500) {
        await sleep(1000 * 2 ** attempt)
        continue
      }
      throw new Error(`${res.status} ${res.statusText} for ${url.split('?')[0]}`)
    } catch (e) {
      if (attempt < retries && !(e instanceof Error && /^\d{3} /.test(e.message))) {
        await sleep(1000 * 2 ** attempt)
        continue
      }
      throw e
    }
  }
}

async function pool<T, R>(items: T[], limit: number, fn: (t: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++
        out[i] = await fn(items[i], i)
      }
    }),
  )
  return out
}

const chunk = <T>(a: T[], n: number) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, i * n + n))
const median = (a: number[]) => {
  if (!a.length) return null
  const s = [...a].sort((x, y) => x - y)
  const m = s.length >> 1
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}
const enc = encodeURIComponent

// ---------------------------------------------------------------- PG Atlas

interface PgProject {
  canonical_id: string
  display_name: string
  project_type: string
  activity_status: ActivityStatus
  category: string | null
  git_owner_url: string | null
  pony_factor: number | null
  criticality_score: number | null
  adoption_score: number | null
}
interface PgProjectDetail extends PgProject {
  metadata?: { description?: string | null; website?: string | null } | null
}
interface PgRepo {
  canonical_id: string
  display_name: string
  visibility: string
  latest_version: string | null
  latest_commit_date: string | null
  repo_url: string | null
  criticality_score: number | null
  adoption_stars: number | null
}
interface PgEdge {
  canonical_id: string
  display_name: string
  vertex_type: 'repo' | 'external-repo'
  version_range: string | null
  confidence: EdgeSource
}
interface PgPage<T> {
  items: T[]
  total: number
}

async function pgAll<T>(path: string): Promise<T[]> {
  const out: T[] = []
  for (let offset = 0; ; offset += 200) {
    const sep = path.includes('?') ? '&' : '?'
    const page = await http<PgPage<T>>(`${PG}${path}${sep}limit=200&offset=${offset}`)
    out.push(...page!.items)
    if (out.length >= page!.total || !page!.items.length) return out
  }
}

// ---------------------------------------------------------------- PURL / version handling

const OSV_ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  golang: 'Go',
  maven: 'Maven',
  gem: 'RubyGems',
  nuget: 'NuGet',
  composer: 'Packagist',
  pub: 'Pub',
  hex: 'Hex',
  githubactions: 'GitHub Actions',
  swift: 'SwiftURL',
}

function parsePurl(purl: string): { type: string; name: string; ecosystem: string } | null {
  const m = /^pkg:([a-z]+)\/(.+)$/.exec(purl)
  if (!m || !OSV_ECOSYSTEM[m[1]]) return null
  const path = decodeURIComponent(m[2].split('@')[0])
  const name = m[1] === 'maven' ? path.replace(/\/([^/]+)$/, ':$1') : path
  return { type: m[1], name, ecosystem: OSV_ECOSYSTEM[m[1]] }
}

const EXACT = /^v?\d+(\.\d+){0,3}([-+.][0-9A-Za-z.-]+)?$/
const LOWER_BOUND = /(?:^|[\s,(])(?:\^|~=?|>=|==|=)?\s*(v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)/

function resolveVersion(range: string | null): { version: string; resolution: Resolution } | null {
  if (!range) return null
  const r = range.trim()
  if (EXACT.test(r)) return { version: r, resolution: 'exact' }
  if (/^[<!]/.test(r) || /\*|x$/i.test(r)) return null // upper bounds / wildcards: lowest version unknown
  const m = LOWER_BOUND.exec(r)
  return m ? { version: m[1], resolution: 'range' } : null
}

// ---------------------------------------------------------------- GitHub

const ghHeaders = { Authorization: `Bearer ${GH_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'stellar-pg-aegis-snapshot' }

interface GhRepoInfo {
  isArchived: boolean
  stargazerCount: number
  isSecurityPolicyEnabled: boolean | null
  securityPolicyUrl: string | null
  policyText: string | null
  depsTool: boolean
}

const POLICY_PATHS = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md', 'security.md']
const DEPS_PATHS = ['.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json', '.github/renovate.json', 'renovate.json5', '.renovaterc', '.renovaterc.json']

const ghRepoKey = (r: { owner: string; name: string }) => `${r.owner}/${r.name}`.toLowerCase()

async function ghGraphqlRepos(repos: { owner: string; name: string }[]): Promise<Map<string, GhRepoInfo>> {
  const out = new Map<string, GhRepoInfo>()
  const missing: { owner: string; name: string }[] = []
  for (const r of repos) {
    const hit = await cacheGet<GhRepoInfo | null>(`gh:gq:${ghRepoKey(r)}`, GH_TTL_MS)
    if (hit === undefined) missing.push(r)
    else if (hit) out.set(ghRepoKey(r), hit)
  }
  if (missing.length) log(`GitHub GraphQL: ${repos.length - missing.length} cached, fetching ${missing.length}`)
  const blob = (alias: string, path: string, text: boolean) => `${alias}: object(expression: "HEAD:${path}") { ... on Blob { ${text ? 'text' : 'byteSize'} } }`
  for (const batch of chunk(missing, 20)) {
    const body = batch
      .map(
        (r, i) => `r${i}: repository(owner: ${JSON.stringify(r.owner)}, name: ${JSON.stringify(r.name)}) {
          isArchived stargazerCount isSecurityPolicyEnabled securityPolicyUrl
          ${POLICY_PATHS.map((p, j) => blob(`p${j}`, p, true)).join(' ')}
          ${DEPS_PATHS.map((p, j) => blob(`d${j}`, p, false)).join(' ')}
        }`,
      )
      .join('\n')
    let res: { data?: Record<string, Record<string, unknown> | null>; errors?: unknown[] } | null = null
    try {
      res = await http('https://api.github.com/graphql', {
        method: 'POST',
        headers: ghHeaders,
        body: JSON.stringify({ query: `{ ${body} }` }),
      })
    } catch (e) {
      log(`GitHub GraphQL batch failed (skipped, will retry next refresh): ${e}`)
      continue
    }
    for (const [i, r] of batch.entries()) {
      const d = res?.data?.[`r${i}`]
      if (!d) continue // not cached so it is retried on the next refresh
      const policy = POLICY_PATHS.map((_, j) => (d[`p${j}`] as { text?: string } | null)?.text).find(Boolean) ?? null
      const info: GhRepoInfo = {
        isArchived: d.isArchived as boolean,
        stargazerCount: d.stargazerCount as number,
        isSecurityPolicyEnabled: d.isSecurityPolicyEnabled as boolean | null,
        securityPolicyUrl: d.securityPolicyUrl as string | null,
        policyText: policy,
        depsTool: DEPS_PATHS.some((_, j) => d[`d${j}`] != null),
      }
      out.set(ghRepoKey(r), info)
      await cacheSet(`gh:gq:${ghRepoKey(r)}`, info)
    }
  }
  return out
}

async function ghOrgPolicy(owner: string): Promise<string | null> {
  const key = `gh:org:${owner.toLowerCase()}`
  const hit = await cacheGet<string | null>(key, GH_TTL_MS)
  if (hit !== undefined) return hit
  const res = await http<{ data?: { repository?: Record<string, { text?: string } | null> | null } }>('https://api.github.com/graphql', {
    method: 'POST',
    headers: ghHeaders,
    body: JSON.stringify({ query: `{ repository(owner: ${JSON.stringify(owner)}, name: ".github") { a: object(expression: "HEAD:SECURITY.md") { ... on Blob { text } } b: object(expression: "HEAD:.github/SECURITY.md") { ... on Blob { text } } } }` }),
  })
  const r = res?.data?.repository
  const text = r?.a?.text ?? r?.b?.text ?? null
  await cacheSet(key, text)
  return text
}

const ghRest = <T>(path: string) => http<T>(`https://api.github.com${path}`, { headers: ghHeaders }, { allow404: true })

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
const URL_RE = /https?:\/\/[^\s)<>\]"'`]+/g
const BOUNTY_HOSTS = /hackerone\.com|immunefi\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|code4rena\.com/i
const FORM_HOSTS = /forms\.gle|docs\.google\.com\/forms|typeform\.com|tally\.so|security\/advisories\/new/i
const IGNORE_EMAIL = /(example\.(com|org)|noreply|no-reply|users\.noreply\.github\.com)$/i

function extractChannels(text: string): { kind: DisclosureChannel['kind']; value: string }[] {
  const out: { kind: DisclosureChannel['kind']; value: string }[] = []
  const seen = new Set<string>()
  const add = (kind: DisclosureChannel['kind'], value: string) => {
    const v = value.replace(/[.,;:]+$/, '')
    if (seen.has(v.toLowerCase())) return
    seen.add(v.toLowerCase())
    out.push({ kind, value: v })
  }
  for (const e of text.match(EMAIL) ?? []) if (!IGNORE_EMAIL.test(e)) add('email', e.toLowerCase())
  for (const u of text.match(URL_RE) ?? []) {
    if (BOUNTY_HOSTS.test(u)) add('bounty', u)
    else if (FORM_HOSTS.test(u)) add('url', u)
  }
  return out
}

// ---------------------------------------------------------------- main

const text = async (url: string) => {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    return res.ok ? res.text() : ''
  } catch {
    return ''
  }
}

// Canonical public-good list from the WG site: slug -> github repos listed on the page.
async function wgSiteList(): Promise<Map<string, string[]>> {
  const index = await text(`${WG_SITE}/projects/`)
  const slugs = [...new Set([...index.matchAll(/href="\/projects\/([a-z0-9-]+)\/?"/g)].map((m) => m[1]))]
  const out = new Map<string, string[]>()
  await pool(slugs, 8, async (slug) => {
    const html = await text(`${WG_SITE}/projects/${slug}/`)
    const repos = [...new Set([...html.matchAll(/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/g)].map((m) => `${m[1].toLowerCase()}/${m[2].toLowerCase().replace(/\.git$/, '').replace(/\.$/, '')}`))].filter(
      (r) => !/^(feathericons|just-the-docs|twbs)\//.test(r),
    )
    out.set(slug, repos)
  })
  return out
}

const ownerOf = (url: string | null) => (url ? /github\.com\/([^/]+)/i.exec(url)?.[1]?.toLowerCase() : undefined)
const repoKey = (url: string | null) => (url ? (/github\.com\/([^/]+)\/([^/#?]+)/i.exec(url)?.slice(1, 3).join('/').toLowerCase() ?? null) : null)

// Site slug (scf-public-goods-maintenance.github.io/projects/<slug>) -> PG Atlas project.
// Curated like PG Atlas's own project-git-mapping.yml: site pages link third-party reference
// repos, so name/repo-overlap matching alone produces false positives (e.g. Stellar (SDF)).
// `id` = PG Atlas canonical_id; `repo` = a repo owned by the project's selected repo list.
const WG_MAP: Record<string, { id?: string; owner?: string; repo?: string }> = {
  'hyperledger-solang': { repo: 'hyperledger-solang/solang' },
  'lumen-loop': { id: 'daoip-5:scf:project:lumen_loop' },
  'obsrvr-radar': { repo: 'withobsrvr/stellarbeat' },
  opengrants: { id: 'daoip-5:scf:project:opengrants' },
  'pg-atlas': { id: 'daoip-5:scf:project:pg_atlas' },
  refractorspace: { repo: 'stellar-expert/refractor' },
  'rust-soroban-client-library': { repo: 'rahul-soshte/rs-soroban-client' },
  scout: { repo: 'coinfabrik/scout-audit' },
  'soroban-scan': { id: 'daoip-5:scf:project:rumble_fish_software_development_-_rfp' },
  'soroban-ret': { id: 'daoip-5:scf:project:soroban_disassembler_(working_title)' },
  'stellar-net-sdk': { repo: 'beans-bv/dotnet-stellar-sdk' },
  'stellar-hardware-wallet-support': { repo: 'ledgerhq/app-stellar' },
  'stellar-registry': { repo: 'stellar-registry/cli' },
  'scaffold-stellar': { repo: 'stellar-scaffold/cli' },
  'soroban-security-portal': { id: 'daoip-5:scf:project:soroban_security_portal' },
  stellaratlas: { id: 'daoip-5:scf:project:stellaratlas' },
  'stellarchain': { id: 'daoip-5:scf:project:stellarchain.io' },
  stellarlight: { id: 'daoip-5:scf:project:stellar_light' },
  'tansu-decentralized-project-governance-on-stellar': { id: 'daoip-5:scf:project:tansu_-_soroban_versioning' },
  'java-stellar-sdk': { id: 'daoip-5:scf:project:java_stellar_sdk' },
  'kmp-stellar-sdk': { id: 'daoip-5:scf:project:kmp_stellar_sdk' },
  'py-stellar-base': { repo: 'stellarcn/py-stellar-base' },
  soropg: { id: 'daoip-5:scf:project:soropg' },
  'stellar-flutter-sdk': { id: 'daoip-5:scf:project:flutter_stellar_sdk' },
  'stellar-ios-mac-sdk': { id: 'daoip-5:scf:project:stellar_ios_mac_sdk' },
  'stellar-php-sdk': { id: 'daoip-5:scf:project:stellar_php_sdk' },
}

// Normalized Security Portal protocol name -> PG Atlas project. Curated like WG_MAP:
// the portal's own naming is free-form, so name-only matching is unreliable. Protocols
// not listed here still match when protocol.url points at a tracked repo or the
// project's website/git_owner_url host.
const PORTAL_MAP: Record<string, { id?: string; owner?: string; repo?: string }> = {
  'stellar security portal': { id: 'daoip-5:scf:project:soroban_security_portal' },
  'soroban security portal': { id: 'daoip-5:scf:project:soroban_security_portal' },
  tansu: { id: 'daoip-5:scf:project:tansu_-_soroban_versioning' },
  'stellar contracts library': { repo: 'openzeppelin/stellar-contracts' },
  'scaffold registry': { repo: 'stellar-registry/cli' },
  soroswap: { owner: 'soroswap' },
  defindex: { repo: 'paltalabs/defindex' },
  allbridge: { owner: 'allbridge-io' },
  'dia oracles': { repo: 'diadata-org/spectra-interoperability' },
  spectra: { repo: 'diadata-org/spectra-interoperability' },
  'volta circuit': { id: 'daoip-5:scf:project:volta_circuit' },
  'volta wallet': { id: 'daoip-5:scf:project:volta_circuit' },
  stellarchain: { id: 'daoip-5:scf:project:stellarchain.io' },
  alula: { id: 'daoip-5:scf:project:alula' },
}

const normName = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()

async function main() {
  await mkdir(CACHE_DIR, { recursive: true })
  log(`PG Atlas: ${PG}`)
  const metadata = await http<PgAtlasMetadata>(`${PG}/metadata`)
  const siteList = await wgSiteList()
  const siteRepos = new Set([...siteList.values()].flat())
  const siteOwners = new Set([...siteRepos].map((r) => r.split('/')[0]))
  log(`WG site lists ${siteList.size} public-good projects with ${siteRepos.size} repos`)

  // Project set: every public-good-typed project + any SCF project that owns a site-listed repo.
  const allPg = await pgAll<PgProject>('/projects')
  const pgProjects = allPg.filter((p) => p.project_type === 'public-good')
  const scfCandidates = allPg.filter((p) => p.project_type !== 'public-good' && siteOwners.has(ownerOf(p.git_owner_url) ?? ''))
  const candRepos = await pool(scfCandidates, 8, (p) => pgAll<PgRepo>(`/projects/${enc(p.canonical_id)}/repos`))
  const matched = scfCandidates.filter((_, i) => candRepos[i].some((r) => siteRepos.has(repoKey(r.repo_url) ?? '')))
  pgProjects.push(...matched)
  log(`${pgProjects.length} projects (${matched.length} matched to the WG site list as scf-projects)`)

  const details = await pool(pgProjects, 8, (p) => http<PgProjectDetail>(`${PG}/projects/${enc(p.canonical_id)}`))
  const reposByProject = await pool(pgProjects, 8, (p) => pgAll<PgRepo>(`/projects/${enc(p.canonical_id)}/repos`))

  // Mark site-listed public goods via the curated slug map and verify coverage.
  const wgSet = new Set<string>()
  const uncovered: string[] = []
  for (const [slug, m] of Object.entries(WG_MAP)) {
    const found = pgProjects.find((p, i) => {
      if (m.id) return p.canonical_id === m.id
      if (m.owner) return ownerOf(p.git_owner_url) === m.owner
      if (m.repo) return reposByProject[i].some((r) => repoKey(r.repo_url) === m.repo)
      return false
    })
    if (found) wgSet.add(found.canonical_id)
    else uncovered.push(slug)
  }
  log(`WG site coverage: ${siteList.size - uncovered.length}/${siteList.size}${uncovered.length ? ` — missing: ${uncovered.join(', ')}` : ''}`)
  const repoOwner = new Map<string, number>()
  reposByProject.forEach((rs, i) => rs.forEach((r) => repoOwner.set(r.canonical_id, i)))
  const allRepos = reposByProject.flat().filter((r) => r.visibility !== 'private')
  log(`${allRepos.length} repos`)

  const depsByRepo = new Map<string, PgEdge[]>()
  await pool(allRepos, 8, async (r, i) => {
    depsByRepo.set(r.canonical_id, (await http<PgEdge[]>(`${PG}/repos/${enc(r.canonical_id)}/depends-on`, {}, { allow404: true })) ?? [])
    if ((i + 1) % 100 === 0) log(`depends-on ${i + 1}/${allRepos.length}`)
  })

  // ---- OSV matching
  type Query = { purl: string; version: string; resolution: Resolution; ecosystem: string; name: string }
  const queries = new Map<string, Query>()
  let depsTotal = 0
  let depsResolved = 0
  for (const edges of depsByRepo.values()) {
    for (const e of edges) {
      if (e.vertex_type !== 'external-repo') continue
      depsTotal++
      const p = parsePurl(e.canonical_id)
      const v = resolveVersion(e.version_range)
      if (!p || !v) continue
      depsResolved++
      queries.set(`${e.canonical_id}@${v.version}`, { purl: e.canonical_id, version: v.version, resolution: v.resolution, ecosystem: p.ecosystem, name: p.name })
    }
  }
  const qList = [...queries.entries()]
  log(`OSV: ${qList.length} unique package versions (${depsResolved}/${depsTotal} dependency edges resolvable)`)
  const hits = new Map<string, string[]>()
  for (const batch of chunk(qList, 500)) {
    const res = await http<{ results: { vulns?: { id: string }[] }[] }>('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: batch.map(([, q]) => ({ package: { purl: q.purl }, version: q.ecosystem === 'Go' ? q.version : q.version.replace(/^v(?=\d)/, '') })) }),
    })
    res!.results.forEach((r, i) => r.vulns?.length && hits.set(batch[i][0], r.vulns.map((v) => v.id)))
  }
  const vulnIds = [...new Set([...hits.values()].flat())]
  log(`OSV: ${vulnIds.length} distinct advisories matched`)
  const osv = new Map<string, OsvVuln>()
  await pool(vulnIds, 10, async (id) => {
    const v = await http<OsvVuln>(`https://api.osv.dev/v1/vulns/${enc(id)}`, {}, { allow404: true })
    if (v && !v.withdrawn) osv.set(id, v)
  })

  // ---- KEV + EPSS
  const kev = new Set(((await http<{ vulnerabilities: { cveID: string }[] }>('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'))?.vulnerabilities ?? []).map((v) => v.cveID))
  const cveOf = (v: OsvVuln) => [v.id, ...(v.aliases ?? [])].filter((a) => a.startsWith('CVE-'))
  const cves = [...new Set([...osv.values()].flatMap(cveOf))]
  const epss = new Map<string, number>()
  for (const batch of chunk(cves, 80)) {
    const r = await http<{ data: { cve: string; epss: string }[] }>(`https://api.first.org/data/v1/epss?cve=${batch.join(',')}`)
    r?.data.forEach((d) => epss.set(d.cve, Number(d.epss)))
  }
  log(`KEV: ${kev.size} entries · EPSS scores for ${epss.size}/${cves.length} CVEs`)

  // ---- findings (pre-priority)
  type RawFinding = Omit<Finding, 'priority' | 'priority_breakdown'>
  const rawFindings: RawFinding[] = []
  for (const r of allRepos) {
    const pi = repoOwner.get(r.canonical_id)!
    const proj = pgProjects[pi]
    const seen = new Set<string>()
    for (const e of depsByRepo.get(r.canonical_id) ?? []) {
      if (e.vertex_type !== 'external-repo') continue
      const v = resolveVersion(e.version_range)
      const p = parsePurl(e.canonical_id)
      if (!v || !p) continue
      for (const id of hits.get(`${e.canonical_id}@${v.version}`) ?? []) {
        const o = osv.get(id)
        const key = `${id}|${e.canonical_id}`
        if (!o || seen.has(key)) continue
        seen.add(key)
        const { severity, cvss } = severityOf(o)
        const { fixed } = affectedFor(o, p.ecosystem, p.name)
        const ids = cveOf(o)
        const confidence: Confidence = e.confidence === 'inferred-shadow' ? 'inferred' : v.resolution === 'exact' ? 'confirmed' : 'possible'
        rawFindings.push({
          id: `${id}|${r.canonical_id}|${e.canonical_id}`,
          repo_id: r.canonical_id,
          repo_name: r.display_name,
          project_id: proj.canonical_id,
          project_name: proj.display_name,
          vuln_id: id,
          summary: o.summary || o.details?.split('\n')[0]?.slice(0, 160) || id,
          package: { purl: `${e.canonical_id}@${v.version}`, name: p.name, ecosystem: p.ecosystem, version: v.version, version_range: e.version_range ?? '', resolution: v.resolution },
          severity,
          cvss,
          kind: kindOf(o),
          kev: ids.some((c) => kev.has(c)),
          epss: ids.map((c) => epss.get(c)).find((x) => x !== undefined) ?? null,
          confidence,
          source: e.confidence,
          reachability: null,
          reachability_trace: null,
          status: 'open',
          fixed_versions: fixed,
          upgrade_hint: fixed[0] ? (UPGRADE_HINT[p.ecosystem]?.(p.name, fixed[0]) ?? null) : null,
          advisory_published: o.published ?? null,
        })
      }
    }
  }
  log(`${rawFindings.length} findings across ${new Set(rawFindings.map((f) => f.repo_id)).size} repos`)

  // ---- blast radius over PG Atlas has-dependents edges
  const dependentsCache = new Map<string, Promise<PgEdge[]>>()
  const dependents = (id: string) => {
    if (!dependentsCache.has(id)) dependentsCache.set(id, http<PgEdge[]>(`${PG}/repos/${enc(id)}/has-dependents`, {}, { allow404: true }).then((x) => (x ?? []).filter((d) => d.vertex_type === 'repo')))
    return dependentsCache.get(id)!
  }
  const repoById = new Map(allRepos.map((r) => [r.canonical_id, r]))
  const reachOf = new Map<string, number>()
  const vulnRepos = new Map<string, Map<string, Confidence>>()
  for (const f of rawFindings) {
    const m = vulnRepos.get(f.vuln_id) ?? new Map<string, Confidence>()
    const rank = { confirmed: 0, possible: 1, inferred: 2 }
    if (!m.has(f.repo_id) || rank[f.confidence] < rank[m.get(f.repo_id)!]) m.set(f.repo_id, f.confidence)
    vulnRepos.set(f.vuln_id, m)
  }
  // pre-fetch dependents level by level so the cache is warm
  let frontier = [...new Set(rawFindings.map((f) => f.repo_id))]
  for (let d = 1; d <= MAX_DEPTH && frontier.length; d++) {
    log(`dependents depth ${d}: ${frontier.length} repos`)
    const lists = await pool(frontier, 8, (id) => dependents(id))
    frontier.forEach((id, i) => d === 1 && reachOf.set(id, lists[i].length))
    frontier = d < MAX_DEPTH ? [...new Set(lists.flat().map((x) => x.canonical_id))].filter((id) => !dependentsCache.has(id)) : []
  }
  log(`dependents fetched for ${dependentsCache.size} repos`)

  const exposures: Record<string, Exposure[]> = {}
  for (const [vid, roots] of vulnRepos) {
    const seen = new Map<string, Exposure>()
    const queue: Exposure[] = [...roots].map(([id, confidence]) => {
      const r = repoById.get(id)!
      const p = pgProjects[repoOwner.get(id)!]
      return { repo_id: id, repo_name: r.display_name, project_id: p.canonical_id, project_name: p.display_name, depth: 1, via: null, criticality_score: r.criticality_score, confidence }
    })
    while (queue.length) {
      const e = queue.shift()!
      const prev = seen.get(e.repo_id)
      if (prev && prev.depth <= e.depth) continue
      seen.set(e.repo_id, e)
      if (e.depth >= MAX_DEPTH) continue
      for (const d of (await dependents(e.repo_id)) ?? []) {
        const own = repoOwner.get(d.canonical_id)
        const r = repoById.get(d.canonical_id)
        queue.push({
          repo_id: d.canonical_id,
          repo_name: d.display_name,
          project_id: own !== undefined ? pgProjects[own].canonical_id : null,
          project_name: own !== undefined ? pgProjects[own].display_name : null,
          depth: e.depth + 1,
          via: e.repo_name,
          criticality_score: r?.criticality_score ?? null,
          confidence: 'inferred',
        })
      }
    }
    exposures[vid] = [...seen.values()].sort((a, b) => a.depth - b.depth || (b.criticality_score ?? -1) - (a.criticality_score ?? -1))
  }

  // ---- priorities
  const maxCrit = Math.max(0, ...allRepos.map((r) => r.criticality_score ?? 0))
  const maxReach = Math.max(0, ...reachOf.values())
  const findings: Finding[] = rawFindings
    .map((f) => {
      const r = repoById.get(f.repo_id)!
      const { priority, breakdown } = computePriority({
        severity: f.severity,
        cvss: f.cvss,
        criticality: logNorm(r.criticality_score, maxCrit),
        kev: f.kev,
        epss: f.epss,
        reach: logNorm(reachOf.get(f.repo_id) ?? 0, maxReach),
        fixAvailable: f.fixed_versions.length > 0,
        confidence: f.confidence,
      })
      return { ...f, priority, priority_breakdown: breakdown }
    })
    .sort((a, b) => b.priority - a.priority)

  // ---- govulncheck reachability for Go findings
  // Clone repos with Go findings (most findings first, GOVC_MAX_REPOS caps), run
  // `govulncheck -json ./...` per module, annotate reachability on each finding.
  const govcResults = new Map<string, ReachVerdicts | null>()
  if (process.env.GOVC === '0') {
    log('govulncheck: disabled via GOVC=0')
  } else {
    const goCount = new Map<string, number>()
    for (const f of findings) if (f.package.ecosystem === 'Go') goCount.set(f.repo_id, (goCount.get(f.repo_id) ?? 0) + 1)
    const goTargets = allRepos
      .map((r) => ({ r, gh: ghRepoOf(r.repo_url), n: goCount.get(r.canonical_id) ?? 0 }))
      .filter((x): x is { r: PgRepo; gh: { owner: string; name: string }; n: number } => x.n > 0 && !!x.gh && (!GOVC_REPOS || GOVC_REPOS.includes(ghKey(x.gh))))
      .sort((a, b) => b.n - a.n)
      .slice(0, GOVC_MAX)
    const bin = goTargets.length ? await govcBinary() : null
    if (goTargets.length && !bin) {
      log('govulncheck: neither govulncheck nor go found — reachability will be "not analyzed"')
    } else if (bin) {
      log(`govulncheck: analyzing ${goTargets.length} Go repos${Number.isFinite(GOVC_MAX) ? ` (capped)` : ''} — this is slow on first run, cached per commit`)
      await mkdir(CLONES_DIR, { recursive: true })
      await pool(goTargets, 3, async ({ r, gh }) => {
        govcResults.set(r.canonical_id, await govcRepo(bin, gh, r.repo_url!))
      })
      const analyzed = [...govcResults.values()].filter(Boolean).length
      const calls = [...govcResults.values()].flatMap((m) => [...(m?.values() ?? [])]).filter((v) => v.v === 'called').length
      log(`govulncheck: ${analyzed}/${goTargets.length} repos analyzed · ${calls} vulnerabilities with a call path`)
    }
    for (const f of findings) {
      if (f.package.ecosystem !== 'Go') continue
      const per = govcResults.get(f.repo_id)
      if (!per) continue // not a target, capped out, or analysis failed
      // govulncheck reports canonical GO- ids; our finding may key on a GHSA alias.
      const hits = [f.vuln_id, ...(osv.get(f.vuln_id)?.aliases ?? [])].map((c) => per.get(c)).filter((x): x is NonNullable<ReturnType<typeof per.get>> => !!x)
      const hit = hits.find((h) => h.v === 'called') ?? hits[0]
      f.reachability = hit?.v ?? 'unflagged'
      f.reachability_trace = hit?.t ?? null
    }

    // Emit new findings for advisories govulncheck reports but edge matching missed —
    // versions come from the repo's own resolved go.mod (strongest version evidence).
    const pend: { vid: string; r: PgRepo; g: { v: Reachability; t: string | null; m: string | null; v2: string | null } }[] = []
    const toFetch = new Set<string>()
    for (const [repoId, per] of govcResults) {
      if (!per) continue
      const r = repoById.get(repoId)
      if (!r) continue
      const matched = new Set(rawFindings.filter((f) => f.repo_id === repoId).flatMap((f) => [f.vuln_id, ...(osv.get(f.vuln_id)?.aliases ?? [])]))
      for (const [osvId, g] of per) {
        if (matched.has(osvId) || !g.m || !g.v2) continue
        pend.push({ vid: osvId, r, g })
        toFetch.add(osvId)
      }
    }
    if (toFetch.size) {
      log(`govulncheck: ${toFetch.size} advisories reported that edge matching missed`)
      await pool([...toFetch], 10, async (id) => {
        const v = await fetchOsv(id)
        if (v && !v.withdrawn) osv.set(id, v)
      })
      let emitted = 0
      for (const { vid, r, g } of pend) {
        const o = osv.get(vid)
        if (!o) continue
        const proj = pgProjects[repoOwner.get(r.canonical_id)!]
        let { severity, cvss } = severityOf(o)
        if (severity === 'unknown') {
          const ghsa = await fetchOsv(o.aliases?.find((a) => a.startsWith('GHSA-')) ?? '')
          if (ghsa) ({ severity, cvss } = severityOf(ghsa))
        }
        const ids = cveOf(o)
        const { fixed } = affectedFor(o, 'Go', g.m!)
        const { priority, breakdown } = computePriority({
          severity,
          cvss,
          criticality: logNorm(r.criticality_score, maxCrit),
          kev: ids.some((c) => kev.has(c)),
          epss: ids.map((c) => epss.get(c)).find((x) => x !== undefined) ?? null,
          reach: logNorm(reachOf.get(r.canonical_id) ?? 0, maxReach),
          fixAvailable: fixed.length > 0,
          confidence: 'confirmed',
        })
        findings.push({
          id: `${vid}|${r.canonical_id}|govulncheck`,
          repo_id: r.canonical_id,
          repo_name: r.display_name,
          project_id: proj.canonical_id,
          project_name: proj.display_name,
          vuln_id: vid,
          summary: o.summary || o.details?.split('\n')[0]?.slice(0, 160) || vid,
          package: { purl: `pkg:golang/${g.m}@${g.v2}`, name: g.m!, ecosystem: 'Go', version: g.v2!, version_range: g.v2!, resolution: 'exact' },
          severity,
          cvss,
          kind: kindOf(o),
          kev: ids.some((c) => kev.has(c)),
          epss: ids.map((c) => epss.get(c)).find((x) => x !== undefined) ?? null,
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
        })
        ;(exposures[vid] ??= []).push({ repo_id: r.canonical_id, repo_name: r.display_name, project_id: proj.canonical_id, project_name: proj.display_name, depth: 1, via: null, criticality_score: r.criticality_score, confidence: 'confirmed' })
        emitted++
      }
      findings.sort((a, b) => b.priority - a.priority)
      log(`govulncheck: emitted ${emitted} new findings`)
    }
  }

  // ---- GitHub enrichment
  // Coverage is incremental: repos with findings first, then by stars. Results are cached
  // per repo, so a capped or interrupted run still keeps its progress and the next
  // `data:refresh` continues where it left off.
  const ghTargetIds = new Set(rawFindings.map((f) => f.repo_id))
  const ghCandidates = allRepos
    .map((r) => ({ r, gh: ghRepoOf(r.repo_url) }))
    .filter((x): x is { r: PgRepo; gh: { owner: string; name: string } } => !!x.gh)
    .sort((a, b) => Number(ghTargetIds.has(b.r.canonical_id)) - Number(ghTargetIds.has(a.r.canonical_id)) || (b.r.adoption_stars ?? 0) - (a.r.adoption_stars ?? 0))
  const GH_MAX = Number(process.env.GH_MAX_REPOS ?? 0) || Infinity
  const ghTargets = ghCandidates.slice(0, GH_MAX)
  const ghRepos = ghTargets.map((t) => t.gh)
  const ghInfo = new Map<string, GhRepoInfo>()
  const pvr = new Map<string, boolean>()
  const advisories = new Map<string, PublishedAdvisory[]>()
  const orgPolicy = new Map<string, string | null>()
  const scorecard = new Map<string, number>()
  const ghDeferred = ghCandidates.length - ghTargets.length
  if (GH_TOKEN) {
    log(`GitHub: enriching ${ghRepos.length}/${ghCandidates.length} repos${ghDeferred ? ` (deferred ${ghDeferred} to a later refresh)` : ''}`)
    try {
      for (const [k, v] of await ghGraphqlRepos(ghRepos)) ghInfo.set(k, v)
      await pool([...new Set(ghRepos.map((r) => r.owner))], 6, async (o) => orgPolicy.set(o.toLowerCase(), await ghOrgPolicy(o)))
      let done = 0
      await pool(ghRepos, 8, async (r) => {
        const key = ghRepoKey(r)
        try {
          const pk = `gh:pvr:${key}`
          const ak = `gh:adv:${key}`
          let pv = await cacheGet<{ enabled: boolean }>(pk, GH_TTL_MS)
          let adv = await cacheGet<PublishedAdvisory[]>(ak, GH_TTL_MS)
          if (pv === undefined) {
            pv = await ghRest<{ enabled: boolean }>(`/repos/${r.owner}/${r.name}/private-vulnerability-reporting`)
            if (pv) await cacheSet(pk, pv)
          }
          if (adv === undefined) {
            const raw = await ghRest<{ ghsa_id: string; cve_id: string | null; severity: string; summary: string; published_at: string; html_url: string }[]>(`/repos/${r.owner}/${r.name}/security-advisories?state=published&per_page=100`)
            adv = (raw ?? []).map((a) => ({ ghsa_id: a.ghsa_id, cve_id: a.cve_id, repo: `${r.owner}/${r.name}`, severity: LABEL[a.severity?.toUpperCase()] ?? 'unknown', summary: a.summary, published_at: a.published_at, url: a.html_url }))
            if (adv) await cacheSet(ak, adv)
          }
          if (pv) pvr.set(key, pv.enabled)
          if (adv) advisories.set(key, adv)
        } catch (e) {
          log(`GitHub REST failed for ${key}: ${e}`)
        }
        if (++done % 100 === 0) log(`GitHub REST ${done}/${ghRepos.length}`)
      })
    } catch (e) {
      log(`GitHub enrichment aborted early, keeping partial results: ${e}`)
    }
  } else {
    log('GITHUB_TOKEN not set — skipping GitHub enrichment (policy / PVR / advisories will be "unknown")')
  }
  await pool(ghRepos, 10, async (r) => {
    const key = ghRepoKey(r)
    const cached = await cacheGet<number | null>(`gh:sc:${key}`, GH_TTL_MS)
    if (cached !== undefined) {
      if (cached != null) scorecard.set(key, cached)
      return
    }
    const s = await http<{ score: number }>(`https://api.securityscorecards.dev/projects/github.com/${r.owner}/${r.name}`, {}, { allow404: true, retries: 1 }).catch(() => null)
    await cacheSet(`gh:sc:${key}`, s?.score ?? null)
    if (s) scorecard.set(key, s.score)
  })
  log(`Scorecard: ${scorecard.size}/${ghRepos.length} repos scored`)

  // ---- security.txt for non-GitHub project websites
  const securityTxt = new Map<number, string>()
  await pool(details, 8, async (d, i) => {
    const w = d?.metadata?.website
    if (!w || /github\.com/i.test(w)) return
    try {
      const origin = new URL(w).origin
      const res = await fetch(`${origin}/.well-known/security.txt`, { signal: AbortSignal.timeout(10_000), redirect: 'follow' })
      const t = res.ok ? await res.text() : ''
      if (/^\s*Contact:/im.test(t) && !/<html/i.test(t)) securityTxt.set(i, `${origin}/.well-known/security.txt`)
    } catch {
      /* unreachable website: leave unknown */
    }
  })

  // ---- Stellar Security Portal audit reports
  // Public unauthenticated API served from the site origin (the portal's deploy passes
  // apiUrl=https://stellarsecurityportal.com to its UI). Only approved reports are
  // surfaced — draft/rejected reports aren't publicly visible to guests.
  interface PortalProtocol {
    id: number
    name: string
    url?: string | null
  }
  interface PortalReport {
    id: number
    name: string
    date: string
    status?: string
    protocolId: number
    protocolName?: string
    auditorName?: string | null
  }
  const auditsByProject = new Map<string, AuditReport[]>()
  const portalFetch = async <T>(key: string, fetcher: () => Promise<T | null>): Promise<T | null> => {
    const hit = await cacheGet<T | null>(`portal:${key}`, CACHE_TTL_MS)
    if (hit !== undefined) return hit
    const v = await fetcher().catch(() => null)
    await cacheSet(`portal:${key}`, v)
    return v
  }
  const portalProtocols = await portalFetch('protocols', () => http<PortalProtocol[]>(`${PORTAL}/protocols`, {}, { retries: 1 }))
  const portalReports = portalProtocols
    ? await portalFetch('reports', () => http<PortalReport[]>(`${PORTAL}/reports`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }, { retries: 1 }))
    : null
  const portalOk = portalProtocols != null && portalReports != null
  if (!portalOk) {
    log('Security Portal: unreachable — audit fields will be "not collected"')
  } else {
    // Hostname matching must skip VCS hosts — github.com URLs are handled by repoKey
    // below; treating the host itself as a signal would match every GitHub-hosted project.
    const VCS_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'sr.ht'])
    const hostOf = (url: string | null | undefined) => {
      if (!url) return null
      try {
        const h = new URL(url).hostname.replace(/^www\./, '').toLowerCase()
        return VCS_HOSTS.has(h) ? null : h
      } catch {
        return null
      }
    }
    const projByRepo = new Map<string, string>()
    reposByProject.forEach((rs, i) => rs.forEach((r) => {
      const k = repoKey(r.repo_url)
      if (k) projByRepo.set(k, pgProjects[i].canonical_id)
    }))
    const projHosts = pgProjects.map((p, i) => new Set([hostOf(details[i]?.metadata?.website), hostOf(p.git_owner_url), ...reposByProject[i].map((r) => hostOf(r.repo_url))].filter((h): h is string => !!h)))
    const findProject = (proto: PortalProtocol): string | null => {
      const m = PORTAL_MAP[normName(proto.name)]
      if (m) {
        const found = pgProjects.find((p, i) => {
          if (m.id) return p.canonical_id === m.id
          if (m.owner) return ownerOf(p.git_owner_url) === m.owner
          if (m.repo) return reposByProject[i].some((r) => repoKey(r.repo_url) === m.repo)
          return false
        })
        if (found) return found.canonical_id
      }
      const rk = repoKey(proto.url ?? null)
      if (rk && projByRepo.has(rk)) return projByRepo.get(rk)!
      const h = hostOf(proto.url)
      if (h) {
        const i = projHosts.findIndex((s) => s.has(h))
        if (i >= 0) return pgProjects[i].canonical_id
      }
      return null
    }
    const reportsByProto = new Map<number, PortalReport[]>()
    for (const r of portalReports.filter((r) => (r.status ?? 'approved').toLowerCase() === 'approved')) {
      const list = reportsByProto.get(r.protocolId) ?? []
      list.push(r)
      reportsByProto.set(r.protocolId, list)
    }
    const unmatched: string[] = []
    for (const proto of portalProtocols) {
      const cid = findProject(proto)
      if (!cid) {
        if (reportsByProto.has(proto.id)) unmatched.push(proto.name)
        continue
      }
      const list = auditsByProject.get(cid) ?? []
      for (const r of reportsByProto.get(proto.id) ?? []) list.push({ id: r.id, name: r.name, auditor: r.auditorName ?? null, date: r.date, url: `${PORTAL_SITE}/report/${r.id}` })
      if (list.length) auditsByProject.set(cid, list)
    }
    for (const list of auditsByProject.values()) list.sort((a, b) => b.date.localeCompare(a.date))
    const matchedReports = [...auditsByProject.values()].reduce((a, l) => a + l.length, 0)
    log(`Security Portal: ${portalProtocols.length} protocols, ${reportsByProto.size} with approved reports — matched ${matchedReports} reports onto ${auditsByProject.size} projects${unmatched.length ? ` · unmatched: ${unmatched.join(', ')}` : ''}`)
  }

  // ---- assemble projects
  const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 })
  const projects: ProjectDetail[] = pgProjects.map((p, i) => {
    const pRepos = reposByProject[i].filter((r) => r.visibility !== 'private')
    const pFindings = findings.filter((f) => f.project_id === p.canonical_id)
    const open_findings = emptyCounts()
    pFindings.forEach((f) => open_findings[f.severity]++)
    const repos: Repo[] = pRepos
      .map((r) => {
        const gh = ghRepoOf(r.repo_url)
        const key = gh ? `${gh.owner}/${gh.name}`.toLowerCase() : ''
        const info = ghInfo.get(key)
        const deps = depsByRepo.get(r.canonical_id) ?? []
        return {
          canonical_id: r.canonical_id,
          display_name: r.display_name,
          repo_url: r.repo_url,
          latest_version: r.latest_version,
          latest_commit_date: r.latest_commit_date,
          criticality_score: r.criticality_score,
          stars: info?.stargazerCount ?? r.adoption_stars,
          archived: info?.isArchived ?? null,
          dependency_count: deps.length,
          sbom_verified: deps.some((d) => d.confidence === 'verified-sbom'),
          open_findings: pFindings.filter((f) => f.repo_id === r.canonical_id).length,
          has_security_policy: info ? !!info.isSecurityPolicyEnabled : null,
          pvr_enabled: pvr.get(key) ?? null,
          scorecard_overall: scorecard.get(key) ?? null,
        }
      })
      .sort((a, b) => (b.stars ?? 0) - (a.stars ?? 0))

    const known = <T>(xs: (T | null)[]) => xs.filter((x): x is T => x !== null)
    const anyTrue = (xs: (boolean | null)[]) => (known(xs).length ? known(xs).some(Boolean) : null)
    const pAdvisories = repos.flatMap((r) => {
      const gh = ghRepoOf(r.repo_url)
      return gh ? (advisories.get(`${gh.owner}/${gh.name}`.toLowerCase()) ?? []) : []
    })
    pAdvisories.sort((a, b) => b.published_at.localeCompare(a.published_at))
    const scores = known(repos.map((r) => r.scorecard_overall))
    const website = details[i]?.metadata?.website ?? null
    const depsTool = repos.map((r) => {
      const gh = ghRepoOf(r.repo_url)
      return gh ? (ghInfo.get(`${gh.owner}/${gh.name}`.toLowerCase())?.depsTool ?? null) : null
    })
    const hygiene: Hygiene = {
      has_security_policy: anyTrue(repos.map((r) => r.has_security_policy)),
      pvr_enabled: anyTrue(repos.map((r) => r.pvr_enabled)),
      has_security_txt: website && !/github\.com/i.test(website) ? securityTxt.has(i) : null,
      dependency_update_tool: anyTrue(depsTool),
      published_advisories_count: GH_TOKEN ? pAdvisories.length : null,
      last_advisory_at: pAdvisories[0]?.published_at ?? null,
      scorecard_overall: scores.length ? Math.max(...scores) : null,
      audit_reports_count: portalOk ? (auditsByProject.get(p.canonical_id)?.length ?? 0) : null,
      last_audit_at: auditsByProject.get(p.canonical_id)?.[0]?.date ?? null,
    }

    // disclosure channels, ranked: PVR > SECURITY.md contacts > security.txt > policy link > fallback
    const channels: Omit<DisclosureChannel, 'rank'>[] = []
    const seen = new Set<string>()
    const push = (c: Omit<DisclosureChannel, 'rank'>) => {
      if (seen.has(c.value.toLowerCase())) return
      seen.add(c.value.toLowerCase())
      channels.push(c)
    }
    for (const r of repos.filter((r) => r.pvr_enabled)) push({ kind: 'pvr', value: `${r.repo_url}/security/advisories/new`, repo: r.display_name, source_url: `${r.repo_url}/security`, extracted_by: 'rule', last_verified_at: NOW })
    for (const r of repos) {
      const gh = ghRepoOf(r.repo_url)
      if (!gh) continue
      const info = ghInfo.get(`${gh.owner}/${gh.name}`.toLowerCase())
      if (!info?.isSecurityPolicyEnabled) continue
      const text = info.policyText ?? orgPolicy.get(gh.owner.toLowerCase()) ?? null
      for (const c of text ? extractChannels(text) : []) push({ ...c, repo: r.display_name, source_url: info.securityPolicyUrl, extracted_by: 'rule', last_verified_at: NOW })
    }
    if (securityTxt.has(i)) push({ kind: 'security_txt', value: securityTxt.get(i)!, repo: null, source_url: securityTxt.get(i)!, extracted_by: 'rule', last_verified_at: NOW })
    const policyRepo = repos.find((r) => r.has_security_policy)
    if (policyRepo) {
      const gh = ghRepoOf(policyRepo.repo_url)!
      const url = ghInfo.get(`${gh.owner}/${gh.name}`.toLowerCase())?.securityPolicyUrl ?? `${policyRepo.repo_url}/security/policy`
      push({ kind: 'policy', value: url, repo: policyRepo.display_name, source_url: url, extracted_by: 'rule', last_verified_at: NOW })
    }
    if (!channels.length && repos[0]?.repo_url && GH_TOKEN) push({ kind: 'other', value: repos[0].repo_url, repo: repos[0].display_name, source_url: repos[0].repo_url, extracted_by: 'rule', last_verified_at: NOW })

    return {
      canonical_id: p.canonical_id,
      display_name: p.display_name,
      wg_listed: wgSet.has(p.canonical_id),
      category: p.category,
      activity_status: p.activity_status,
      criticality_score: p.criticality_score,
      adoption_score: p.adoption_score,
      pony_factor: p.pony_factor,
      git_owner_url: p.git_owner_url,
      repo_count: repos.length,
      open_findings,
      max_priority: pFindings[0]?.priority ?? 0,
      hygiene,
      description: details[i]?.metadata?.description ?? null,
      website: details[i]?.metadata?.website ?? null,
      repos,
      findings: pFindings,
      disclosure: channels.map((c, k) => ({ ...c, rank: k + 1 })),
      published_advisories: pAdvisories,
      audits: auditsByProject.get(p.canonical_id) ?? [],
    }
  })

  // ---- vulns
  const vulns: Vuln[] = [...osv.values()]
    .filter((o) => exposures[o.id])
    .map((o) => {
      const f = findings.find((x) => x.vuln_id === o.id)!
      const { severity, cvss, vector } = severityOf(o)
      const { fixed, range } = affectedFor(o, f.package.ecosystem, f.package.name)
      const ex = exposures[o.id]
      return {
        id: o.id,
        aliases: o.aliases ?? [],
        summary: f.summary,
        details: (o.details ?? '').slice(0, 1500),
        severity,
        cvss,
        cvss_vector: vector,
        kind: kindOf(o),
        published: o.published ?? null,
        modified: o.modified ?? null,
        kev: f.kev,
        epss: f.epss,
        ecosystem: f.package.ecosystem,
        package: f.package.name,
        affected_range: range,
        fixed_versions: fixed,
        references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${o.id}` }, ...(o.references ?? []).slice(0, 8)],
        exposed_projects: new Set(ex.map((e) => e.project_id ?? e.repo_id)).size,
        exposed_repos: ex.length,
      }
    })
    .sort((a, b) => b.exposed_repos - a.exposed_repos || (b.cvss ?? 0) - (a.cvss ?? 0))

  // ---- summary
  const open = emptyCounts()
  findings.forEach((f) => open[f.severity]++)
  const share = (fn: (p: ProjectDetail) => boolean | null) => {
    const vals = projects.map(fn).filter((x) => x !== null)
    return vals.length ? vals.filter(Boolean).length / vals.length : null
  }
  const ecoMap = new Map<string, { findings: number; repos: Set<string> }>()
  for (const f of findings) {
    const e = ecoMap.get(f.package.ecosystem) ?? { findings: 0, repos: new Set<string>() }
    e.findings++
    e.repos.add(f.repo_id)
    ecoMap.set(f.package.ecosystem, e)
  }
  const fixableAges = findings.filter((f) => f.fixed_versions.length && f.advisory_published).map((f) => (Date.parse(NOW) - Date.parse(f.advisory_published!)) / 86_400_000)
  const summary: EcosystemSummary = {
    projects_tracked: projects.length,
    repos_tracked: allRepos.length,
    sbom_coverage: projects.filter((p) => p.repos.some((r) => r.sbom_verified)).length / Math.max(1, projects.length),
    policy_coverage: share((p) => p.hygiene.has_security_policy),
    pvr_coverage: share((p) => p.hygiene.pvr_enabled),
    open_findings: open,
    affected_projects: new Set(findings.map((f) => f.project_id)).size,
    kev_findings: findings.filter((f) => f.kev).length,
    fixable_findings: findings.filter((f) => f.fixed_versions.length > 0).length,
    reachability: govcResults.size
      ? findings.reduce((a, f) => (f.reachability ? { ...a, [f.reachability]: a[f.reachability] + 1 } : a), { called: 0, 'not-called': 0, unflagged: 0 } as Record<Reachability, number>)
      : null,
    median_fixable_advisory_age_days: median(fixableAges) !== null ? Math.round(median(fixableAges)!) : null,
    audit_coverage: portalOk
      ? (() => {
          const wg = projects.filter((p) => p.wg_listed)
          return wg.length ? wg.filter((p) => p.audits.length > 0).length / wg.length : null
        })()
      : null,
    dependencies_total: depsTotal,
    dependencies_resolved: depsResolved,
    by_ecosystem: [...ecoMap.entries()].map(([ecosystem, v]) => ({ ecosystem, findings: v.findings, repos: v.repos.size })).sort((a, b) => b.findings - a.findings),
    pg_atlas: metadata,
    generated_at: NOW,
    sources: ['PG Atlas', 'OSV.dev', 'CISA KEV', 'FIRST EPSS', 'OpenSSF Scorecard', ...(GH_TOKEN ? ['GitHub'] : []), ...(govcResults.size ? ['govulncheck'] : []), ...(portalOk ? ['Stellar Security Portal'] : [])],
  }

  const snapshot: Snapshot = { summary, projects, vulns, exposures }
  await mkdir(dirname(OUT), { recursive: true })
  await writeFile(OUT, JSON.stringify(snapshot))
  log(`wrote ${OUT} — ${projects.length} projects, ${findings.length} findings, ${vulns.length} advisories`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
