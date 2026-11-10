import type { ActivityStatus, ChannelKind, Severity } from '../api/types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  unknown: '#94a3b8',
}

export const STATUS_LABEL: Record<ActivityStatus, string> = {
  live: 'Live',
  'in-dev': 'In development',
  discontinued: 'Discontinued',
  'non-responsive': 'Non-responsive',
}

export const CHANNEL_LABEL: Record<ChannelKind, string> = {
  pvr: 'GitHub Private Vulnerability Reporting',
  email: 'Security email (SECURITY.md)',
  url: 'Reporting URL',
  bounty: 'Bug bounty program',
  security_txt: 'security.txt',
  policy: 'SECURITY.md policy',
  other: 'Repository contact',
}

export const pct = (n: number, digits = 0) => `${(n * 100).toFixed(digits)}%`

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

export function relativeTime(iso: string | null, now = Date.now()) {
  if (!iso) return 'unknown'
  const diff = (new Date(iso).getTime() - now) / 1000
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31_536_000],
    ['month', 2_592_000],
    ['week', 604_800],
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60],
  ]
  for (const [unit, sec] of units) if (Math.abs(diff) >= sec) return rtf.format(Math.round(diff / sec), unit)
  return 'just now'
}

export const shortDate = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString('en', { month: 'short', day: 'numeric', year: 'numeric' }) : '—')

export const totalFindings = (c: Record<Severity, number>) => SEVERITIES.reduce((a, s) => a + c[s], 0)
