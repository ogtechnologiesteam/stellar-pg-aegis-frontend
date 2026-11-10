import { ApiError, type AegisApi } from './client'
import type { Paginated, ProjectDetail, ProjectSummary, Severity, Snapshot } from './types'

// Reads the static snapshot built by `npm run data:refresh` from real public sources.
let snapshot: Promise<Snapshot> | null = null
export const loadSnapshot = () =>
  (snapshot ??= fetch(`${import.meta.env.BASE_URL}data/snapshot.json`).then((r) => {
    if (!r.ok) throw new ApiError(r.status, 'Snapshot not found — run `npm run data:refresh`')
    return r.json() as Promise<Snapshot>
  }))

const page = <T>(items: T[], limit = 50, offset = 0): Paginated<T> => ({ items: items.slice(offset, offset + limit), total: items.length, limit, offset })

const SEV_WEIGHT: Record<Severity, number> = { critical: 10_000, high: 1000, medium: 100, low: 10, unknown: 1 }
const findingWeight = (p: ProjectSummary) => (Object.keys(SEV_WEIGHT) as Severity[]).reduce((a, s) => a + p.open_findings[s] * SEV_WEIGHT[s], 0)

const SUMMARY_KEYS = ['canonical_id', 'display_name', 'wg_listed', 'category', 'activity_status', 'criticality_score', 'adoption_score', 'pony_factor', 'git_owner_url', 'repo_count', 'open_findings', 'max_priority', 'hygiene'] as const satisfies readonly (keyof ProjectSummary)[]
const toSummary = (p: ProjectDetail) => Object.fromEntries(SUMMARY_KEYS.map((k) => [k, p[k]])) as unknown as ProjectSummary

const matches = (haystack: string, needle?: string) => !needle || haystack.toLowerCase().includes(needle.toLowerCase())

export const snapshotClient: AegisApi = {
  mode: 'snapshot',
  getSummary: async () => (await loadSnapshot()).summary,
  listProjects: async ({ search, activity_status, has_policy, kev, fixable, wg_listed, sort = 'priority', limit, offset } = {}) => {
    const { projects } = await loadSnapshot()
    const items = projects
      .filter((p) => !kev || p.findings.some((f) => f.kev))
      .filter((p) => !fixable || p.findings.some((f) => f.fixed_versions.length > 0))
      .filter((p) => wg_listed === undefined || p.wg_listed === wg_listed)
      .map(toSummary)
      .filter((p) => matches(`${p.display_name} ${p.canonical_id} ${p.category ?? ''}`, search))
      .filter((p) => !activity_status || p.activity_status === activity_status)
      .filter((p) => has_policy === undefined || p.hygiene.has_security_policy === has_policy)
      .sort((a, b) => {
        if (sort === 'name') return a.display_name.localeCompare(b.display_name)
        if (sort === 'criticality') return (b.criticality_score ?? -1) - (a.criticality_score ?? -1)
        if (sort === 'findings') return findingWeight(b) - findingWeight(a)
        return b.max_priority - a.max_priority || (b.criticality_score ?? -1) - (a.criticality_score ?? -1)
      })
    return page(items, limit, offset)
  },
  getProject: async (id) => {
    const p = (await loadSnapshot()).projects.find((x) => x.canonical_id === id)
    if (!p) throw new ApiError(404, `Project ${id} not found`)
    return p
  },
  listFindings: async ({ limit, dedupe } = {}) => {
    const all = (await loadSnapshot()).projects.flatMap((p) => p.findings).sort((a, b) => b.priority - a.priority)
    const items = dedupe === 'project' ? all.filter((f, i) => all.findIndex((x) => x.project_id === f.project_id) === i) : all
    return page(items, limit)
  },
  listVulns: async ({ search, severity, ecosystem, sort = 'newest', limit, offset } = {}) => {
    const items = (await loadSnapshot()).vulns
      .filter((v) => matches(`${v.id} ${v.package} ${v.summary} ${v.aliases.join(' ')}`, search))
      .filter((v) => !severity || v.severity === severity)
      .filter((v) => !ecosystem || v.ecosystem === ecosystem)
      .sort((a, b) => {
        const av = a.published ?? (sort === 'oldest' ? '9999' : '')
        const bv = b.published ?? (sort === 'oldest' ? '9999' : '')
        return sort === 'oldest' ? av.localeCompare(bv) : bv.localeCompare(av)
      })
    return page(items, limit, offset)
  },
  getVulnExposure: async (id) => {
    const s = await loadSnapshot()
    const vuln = s.vulns.find((v) => v.id === id)
    if (!vuln) throw new ApiError(404, `Advisory ${id} not found`)
    return { vuln, exposures: s.exposures[id] ?? [] }
  },
  lookupDisclosure: async (query) => {
    const q = query.trim()
    if (!q) return []
    const hits = (await loadSnapshot()).projects.filter((p) => matches(`${p.display_name} ${p.canonical_id} ${p.repos.map((r) => `${r.display_name} ${r.repo_url ?? ''}`).join(' ')}`, q))
    return hits.slice(0, 10).map((p) => ({ project: toSummary(p), channels: p.disclosure }))
  },
}
