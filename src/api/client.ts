import type {
  DisclosureLookup,
  EcosystemSummary,
  Finding,
  Paginated,
  ProjectDetail,
  ProjectQuery,
  ProjectSummary,
  VulnExposure,
  Vuln,
  VulnQuery,
} from './types'

export interface AegisApi {
  readonly mode: 'live' | 'snapshot'
  getSummary(): Promise<EcosystemSummary>
  listProjects(q?: ProjectQuery): Promise<Paginated<ProjectSummary>>
  getProject(id: string): Promise<ProjectDetail>
  listFindings(q?: { limit?: number; dedupe?: 'project' }): Promise<Paginated<Finding>>
  listVulns(q?: VulnQuery): Promise<Paginated<Vuln>>
  getVulnExposure(id: string): Promise<VulnExposure>
  lookupDisclosure(query: string): Promise<DisclosureLookup[]>
}

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function qs(params: object = {}) {
  const s = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') s.set(k, String(v))
  const str = s.toString()
  return str ? `?${str}` : ''
}

export function createHttpClient(baseUrl: string): AegisApi {
  const get = async <T>(path: string): Promise<T> => {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/v1${path}`, { headers: { Accept: 'application/json' } })
    if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`)
    return res.json() as Promise<T>
  }
  const enc = encodeURIComponent
  return {
    mode: 'live',
    getSummary: () => get('/ecosystem/summary'),
    listProjects: (q) => get(`/projects${qs(q)}`),
    getProject: (id) => get(`/projects/${enc(id)}`),
    listFindings: (q) => get(`/findings${qs(q)}`),
    listVulns: (q) => get(`/vulns${qs(q)}`),
    getVulnExposure: (id) => get(`/vulns/${enc(id)}/exposure`),
    lookupDisclosure: (query) => get(`/disclosure${qs({ q: query })}`),
  }
}
