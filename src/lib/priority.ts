import type { Confidence, PriorityBreakdown, Severity } from '../api/types.ts'

// Default weights from Specification.md FR5. Kept in sync with the backend config.
export const PRIORITY_WEIGHTS = {
  severity: 35,
  criticality: 25,
  exploitability: 15,
  exposure: 10,
  fix_available: 10,
  confidence_penalty: 15,
} as const

const CONFIDENCE_PENALTY: Record<Confidence, number> = { confirmed: 0, possible: 0.5, inferred: 1 }

// Used only when an advisory has no computable CVSS score.
export const SEVERITY_NORM: Record<Severity, number> = { critical: 0.95, high: 0.8, medium: 0.55, low: 0.25, unknown: 0.4 }

export interface PriorityInput {
  severity: Severity
  cvss: number | null
  /** 0–1, log-normalized PG Atlas criticality of the affected repo */
  criticality: number
  kev: boolean
  epss: number | null
  /** 0–1, log-normalized count of downstream repos that depend on the affected repo */
  reach: number
  fixAvailable: boolean
  confidence: Confidence
}

export const logNorm = (value: number | null, max: number) => (value && max > 0 ? Math.log1p(value) / Math.log1p(max) : 0)

export function computePriority(i: PriorityInput): { priority: number; breakdown: PriorityBreakdown } {
  const w = PRIORITY_WEIGHTS
  const breakdown: PriorityBreakdown = {
    severity: w.severity * (i.cvss != null ? i.cvss / 10 : SEVERITY_NORM[i.severity]),
    criticality: w.criticality * i.criticality,
    exploitability: w.exploitability * (i.kev ? 1 : (i.epss ?? 0)),
    exposure: w.exposure * i.reach,
    fix_available: w.fix_available * (i.fixAvailable ? 1 : 0),
    confidence_penalty: -w.confidence_penalty * CONFIDENCE_PENALTY[i.confidence],
  }
  const total = Object.values(breakdown).reduce((a, b) => a + b, 0)
  return { priority: Math.round(Math.max(0, Math.min(100, total))), breakdown }
}
