// Mirrors the read API described in Specification.md §5 (FR10) and §8.2.
// Field semantics follow PG Atlas: `criticality_score` is an integer count of transitive
// in-ecosystem dependents, `adoption_score` is a 0–100 composite. `null` always means
// "not collected / unknown" — never a guessed value.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type ActivityStatus = 'live' | 'in-dev' | 'discontinued' | 'non-responsive'
export type Confidence = 'confirmed' | 'possible' | 'inferred'
/** govulncheck call-analysis verdict (Go repos only). Orthogonal to confidence:
 * 'called' = a call path into a vulnerable symbol exists; 'not-called' = the advisory
 * matches the repo's modules but no call path was found; 'unflagged' = govulncheck
 * analyzed the repo at HEAD and did not report the advisory at all (the resolved
 * module may differ from the PG Atlas edge, or already be patched). */
export type Reachability = 'called' | 'not-called' | 'unflagged'
export type FindingStatus = 'open' | 'fixed' | 'withdrawn' | 'ignored'
export type Resolution = 'exact' | 'range'
export type EdgeSource = 'verified-sbom' | 'inferred-shadow' | 'govulncheck'
export type ChannelKind = 'pvr' | 'email' | 'url' | 'bounty' | 'security_txt' | 'policy' | 'other'
export type ExtractedBy = 'rule' | 'llm' | 'manual'

export type SeverityCounts = Record<Severity, number>

export interface Paginated<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface DisclosureChannel {
  kind: ChannelKind
  value: string
  rank: number
  repo: string | null
  source_url: string | null
  extracted_by: ExtractedBy
  last_verified_at: string
}

export interface Hygiene {
  has_security_policy: boolean | null
  pvr_enabled: boolean | null
  has_security_txt: boolean | null
  dependency_update_tool: boolean | null
  published_advisories_count: number | null
  last_advisory_at: string | null
  scorecard_overall: number | null
}

export interface ProjectSummary {
  canonical_id: string
  display_name: string
  /** Listed on the WG site (scf-public-goods-maintenance.github.io/projects) — the canonical public-goods set. */
  wg_listed: boolean
  category: string | null
  activity_status: ActivityStatus
  criticality_score: number | null
  adoption_score: number | null
  pony_factor: number | null
  git_owner_url: string | null
  repo_count: number
  open_findings: SeverityCounts
  max_priority: number
  hygiene: Hygiene
}

export interface Repo {
  canonical_id: string
  display_name: string
  repo_url: string | null
  latest_version: string | null
  latest_commit_date: string | null
  criticality_score: number | null
  stars: number | null
  archived: boolean | null
  dependency_count: number
  sbom_verified: boolean
  open_findings: number
  has_security_policy: boolean | null
  pvr_enabled: boolean | null
  scorecard_overall: number | null
}

export interface PriorityBreakdown {
  severity: number
  criticality: number
  exploitability: number
  exposure: number
  fix_available: number
  confidence_penalty: number
}

export interface FindingPackage {
  purl: string
  name: string
  ecosystem: string
  version: string
  version_range: string
  resolution: Resolution
}

export interface Finding {
  id: string
  repo_id: string
  repo_name: string
  project_id: string
  project_name: string
  vuln_id: string
  summary: string
  package: FindingPackage
  severity: Severity
  cvss: number | null
  kev: boolean
  epss: number | null
  confidence: Confidence
  source: EdgeSource
  /** null = not analyzed (non-Go, non-GitHub, or govulncheck unavailable/failed). */
  reachability: Reachability | null
  /** For 'called': "pkg.VulnFunc ← entrypkg.caller" from the govulncheck trace. */
  reachability_trace: string | null
  status: FindingStatus
  priority: number
  priority_breakdown: PriorityBreakdown
  fixed_versions: string[]
  upgrade_hint: string | null
  advisory_published: string | null
}

export interface PublishedAdvisory {
  ghsa_id: string
  cve_id: string | null
  repo: string
  severity: Severity
  summary: string
  published_at: string
  url: string
}

export interface ProjectDetail extends ProjectSummary {
  description: string | null
  website: string | null
  repos: Repo[]
  findings: Finding[]
  disclosure: DisclosureChannel[]
  published_advisories: PublishedAdvisory[]
}

export interface Reference {
  type: string
  url: string
}

export interface Vuln {
  id: string
  aliases: string[]
  summary: string
  details: string
  severity: Severity
  cvss: number | null
  cvss_vector: string | null
  published: string | null
  modified: string | null
  kev: boolean
  epss: number | null
  ecosystem: string
  package: string
  affected_range: string
  fixed_versions: string[]
  references: Reference[]
  exposed_projects: number
  exposed_repos: number
}

export interface Exposure {
  repo_id: string
  repo_name: string
  project_id: string | null
  project_name: string | null
  depth: number
  via: string | null
  criticality_score: number | null
  confidence: Confidence
}

export interface VulnExposure {
  vuln: Vuln
  exposures: Exposure[]
}

export interface EcosystemCount {
  ecosystem: string
  findings: number
  repos: number
}

export interface PgAtlasMetadata {
  total_projects: number
  active_projects: number
  total_repos: number
  total_external_repos: number
  total_dependency_edges: number
  last_updated: string
}

export interface EcosystemSummary {
  projects_tracked: number
  repos_tracked: number
  sbom_coverage: number
  policy_coverage: number | null
  pvr_coverage: number | null
  open_findings: SeverityCounts
  affected_projects: number
  kev_findings: number
  fixable_findings: number
  /** govulncheck verdict counts across Go findings. null = call analysis never ran. */
  reachability: Record<Reachability, number> | null
  median_fixable_advisory_age_days: number | null
  dependencies_total: number
  dependencies_resolved: number
  by_ecosystem: EcosystemCount[]
  pg_atlas: PgAtlasMetadata | null
  generated_at: string
  sources: string[]
}

export interface ProjectQuery {
  search?: string
  activity_status?: ActivityStatus
  has_policy?: boolean
  kev?: boolean
  fixable?: boolean
  /** Has ≥1 finding where govulncheck found a call path into a vulnerable symbol. */
  reachable?: boolean
  wg_listed?: boolean
  sort?: 'priority' | 'criticality' | 'name' | 'findings'
  limit?: number
  offset?: number
}

export interface VulnQuery {
  search?: string
  severity?: Severity
  ecosystem?: string
  sort?: 'newest' | 'oldest'
  limit?: number
  offset?: number
}

export interface DisclosureLookup {
  project: ProjectSummary
  channels: DisclosureChannel[]
}

/** Static snapshot produced by `scripts/build-snapshot.ts` (stand-in for the backend). */
export interface Snapshot {
  summary: EcosystemSummary
  projects: ProjectDetail[]
  vulns: Vuln[]
  exposures: Record<string, Exposure[]>
}
