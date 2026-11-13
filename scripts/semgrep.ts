// Semgrep SAST pass: reuses the shared clone pool (govulncheck.ts ensureClone),
// runs `semgrep scan --json` per repo, and returns deduplicated findings.
// Results are cached per commit SHA + semgrep version + ruleset name (immutable;
// 30d TTL so registry rule drift is picked up periodically). SAST findings are
// orthogonal to vulnerability findings — no CVE/priority semantics.
import { execFile } from 'node:child_process'
import { homedir } from 'node:os'
import { stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import { promisify } from 'node:util'
import type { SastFinding, SastSeverity } from '../src/api/types.ts'
import { cacheGet, cacheSet, log } from './cache.ts'
import { ensureClone, GOVC_TTL_MS } from './govulncheck.ts'

const execP = promisify(execFile)

/** Semgrep CLI pin — bump deliberately; recorded in cache keys and summary.sast. */
export const SEMGREP_VERSION = process.env.SEMGREP_VERSION ?? '1.184.0'
/** Registry ruleset — `p/*` rules are mutable upstream; the cache key records the
 * name so changing rulesets rescans everything. */
export const SEMGREP_CONFIG = process.env.SEMGREP_CONFIG ?? 'p/security-audit'
export const SEMGREP_MAX = Number(process.env.SEMGREP_MAX_REPOS ?? 0) || Infinity
/** Comma-separated owner/name filter — restrict analysis to specific repos. */
export const SEMGREP_REPOS = process.env.SEMGREP_REPOS?.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
/** Findings kept per repo — bounds snapshot size on noisy repos. */
const PER_REPO_CAP = 100

async function sh(cmd: string, args: string[], cwd: string, timeout = 120_000, env?: Record<string, string>): Promise<{ out: string; err: string; ok: boolean }> {
  try {
    const { stdout, stderr } = await execP(cmd, args, { cwd, timeout, maxBuffer: 128 * 1024 * 1024, env: { ...process.env, ...env } })
    return { out: String(stdout), err: String(stderr), ok: true }
  } catch (e) {
    const x = e as { stdout?: string | Buffer; stderr?: string | Buffer }
    return { out: String(x.stdout ?? ''), err: String(x.stderr ?? e), ok: false }
  }
}

let sgBin: string | null | undefined
export async function semgrepBinary(): Promise<string | null> {
  if (sgBin !== undefined) return sgBin
  if ((await sh('which', ['semgrep'], '.')).ok) return (sgBin = 'semgrep')
  if (!(await sh('python3', ['--version'], '.')).ok) return (sgBin = null)
  // `pip install --user` lands in the platform user-base bin dir — ~/.local/bin on
  // Linux, ~/Library/Python/X.Y/bin on macOS. Ask python where that is.
  const userBase = (await sh('python3', ['-m', 'site', '--user-base'], '.')).out.trim()
  const userBin = userBase ? `${userBase}/bin/semgrep` : `${homedir()}/.local/bin/semgrep`
  if (await stat(userBin).then(() => true, () => false)) return (sgBin = userBin)
  log(`semgrep not found — running \`python3 -m pip install --user semgrep==${SEMGREP_VERSION}\``)
  if ((await sh('python3', ['-m', 'pip', 'install', '--user', `semgrep==${SEMGREP_VERSION}`], '.', 600_000)).ok && (await stat(userBin).then(() => true, () => false))) return (sgBin = userBin)
  // Fall back to a bare `semgrep` on PATH — pip may have installed it elsewhere on PATH already.
  if ((await sh('which', ['semgrep'], '.')).ok) return (sgBin = 'semgrep')
  return (sgBin = null)
}

// The OCaml `semgrep` launcher execs `pysemgrep` by name — it must be on PATH.
// A user-site install is usually NOT on PATH, so prefix the bin's own dir.
const sgEnv = (bin: string) => (bin === 'semgrep' ? undefined : { PATH: `${dirname(bin)}:${process.env.PATH}` })

export async function semgrepVersion(bin: string): Promise<string | null> {
  const v = await sh(bin, ['--version'], '.', 30_000, sgEnv(bin))
  return v.ok ? v.out.trim() || null : null
}

interface SgResult {
  check_id?: string
  path?: string
  start?: { line?: number; col?: number }
  end?: { line?: number; col?: number }
  extra?: {
    severity?: string
    message?: string
    lines?: string
    fingerprint?: string
    metadata?: { cwe?: string[] | string; owasp?: string[] | string }
  }
}

const SEV_ORDER: Record<SastSeverity, number> = { error: 0, warning: 1, info: 2 }
const strList = (v: string[] | string | undefined) => (Array.isArray(v) ? v : v ? [v] : [])
const trim = (s: string | undefined, n: number) => (s ? s.replace(/\s+$/, '').slice(0, n) : null)

export interface SastContext {
  repo_id: string
  repo_name: string
  project_id: string
  project_name: string
}

/** Clone (or refresh) the repo, run `semgrep scan --json`, return findings +
 * scanned sha. null = could not analyze (clone or scan failed). */
export async function sastRepo(bin: string, gh: { owner: string; name: string }, url: string, ctx: SastContext): Promise<{ sha: string; findings: SastFinding[] } | null> {
  const key = `${gh.owner}/${gh.name}`.toLowerCase()
  const clone = await ensureClone(gh, url)
  if (!clone) {
    log(`semgrep: clone failed for ${key}`)
    return null
  }
  const { dir, sha } = clone
  const ck = `sast1:${SEMGREP_VERSION}:${SEMGREP_CONFIG}:${key}@${sha}`
  const hit = await cacheGet<{ findings: SastFinding[] } | null>(ck, GOVC_TTL_MS)
  if (hit !== undefined) return hit ? { sha, findings: hit.findings } : null
  const run = await sh(
    bin,
    [
      'scan',
      '--config', SEMGREP_CONFIG,
      '--json',
      '--jobs', '1',
      '--max-memory', '5000',
      '--timeout', '30',
      '--metrics=off',
      '--disable-version-check',
      '--exclude', '*.min.js',
      '--exclude', 'node_modules',
      '--exclude', 'vendor',
      '--exclude', 'dist',
      '--exclude', 'build',
      '.',
    ],
    dir,
    420_000,
    sgEnv(bin),
  )
  // semgrep exits 1 when findings exist; only treat 0/1 with parseable JSON as success.
  let results: SgResult[]
  try {
    results = (JSON.parse(run.out) as { results?: SgResult[] }).results ?? []
  } catch {
    log(`semgrep failed in ${key} — ${run.err.trim().split('\n')[0]?.slice(0, 160)}`)
    await cacheSet(ck, null)
    return null
  }
  const seen = new Set<string>()
  const findings: SastFinding[] = []
  for (const r of results) {
    if (!r.check_id || !r.path) continue
    const sev = (r.extra?.severity ?? 'INFO').toLowerCase()
    const severity: SastSeverity = sev === 'error' ? 'error' : sev === 'warning' ? 'warning' : 'info'
    // extra.fingerprint is the literal "requires login" sentinel in OSS builds —
    // identity is rule + location instead.
    const fp = `${r.path}:${r.start?.line ?? 0}:${r.start?.col ?? 0}`
    const f: SastFinding = {
      id: `${ctx.repo_id}|${r.check_id}|${fp}`,
      ...ctx,
      rule_id: r.check_id,
      message: trim(r.extra?.message, 400) ?? r.check_id,
      severity,
      path: r.path,
      start_line: r.start?.line ?? 0,
      end_line: r.end?.line ?? r.start?.line ?? 0,
      snippet: trim(r.extra?.lines, 500),
      commit_sha: sha,
      cwe: strList(r.extra?.metadata?.cwe),
      owasp: strList(r.extra?.metadata?.owasp),
    }
    if (seen.has(`${r.check_id}|${fp}`)) continue
    seen.add(`${r.check_id}|${fp}`)
    findings.push(f)
  }
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.rule_id.localeCompare(b.rule_id))
  const capped = findings.slice(0, PER_REPO_CAP)
  await cacheSet(ck, { findings: capped })
  return { sha, findings: capped }
}
