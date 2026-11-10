import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { createHttpClient, type AegisApi } from './client'
import { snapshotClient } from './snapshotClient'
import type { ProjectQuery, VulnQuery } from './types'

const baseUrl = import.meta.env.VITE_API_BASE_URL

// Uses the live Aegis backend when configured; otherwise the static snapshot built from real
// public sources by `npm run data:refresh`.
export const api: AegisApi = baseUrl ? createHttpClient(baseUrl) : snapshotClient

export const useSummary = () => useQuery({ queryKey: ['summary'], queryFn: () => api.getSummary() })

export const useProjects = (q: ProjectQuery = {}) =>
  useQuery({ queryKey: ['projects', q], queryFn: () => api.listProjects(q), placeholderData: keepPreviousData })

export const useProject = (id: string) => useQuery({ queryKey: ['project', id], queryFn: () => api.getProject(id) })

export const useFindings = (limit = 10) => useQuery({ queryKey: ['findings', limit], queryFn: () => api.listFindings({ limit }) })

export const useVulns = (q: VulnQuery = {}) =>
  useQuery({ queryKey: ['vulns', q], queryFn: () => api.listVulns(q), placeholderData: keepPreviousData })

export const useVulnExposure = (id: string) => useQuery({ queryKey: ['vuln', id], queryFn: () => api.getVulnExposure(id) })

export const useDisclosureLookup = (query: string) =>
  useQuery({ queryKey: ['disclosure', query], queryFn: () => api.lookupDisclosure(query), enabled: query.trim().length > 0, placeholderData: keepPreviousData })
