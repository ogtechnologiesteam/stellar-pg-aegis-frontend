// govulncheck call analysis: shallow-clones a repo, runs `govulncheck -json ./...` in
// every directory containing go.mod, and returns a per-OSV reachability verdict.
// Reachability is call-graph evidence, orthogonal to edge confidence: govulncheck
// resolves the repo's real module versions at HEAD and checks call paths into the
// symbols each Go advisory names. Verdicts are cached per commit SHA (immutable).
import { execFile } from 'node:child_process'
import { mkdir, readdir, rm, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import { promisify } from 'node:util'
import type { Reachability } from '../src/api/types.ts'
import { CACHE_DIR, cacheGet, cacheSet, log } from './cache.ts'

const execP = promisify(execFile)
export const CLONES_DIR = resolve(CACHE_DIR, 'clones')
export const GOVC_TTL_MS = 30 * 24 * 3600_000
export const GOVC_MAX = Number(process.env.GOVC_MAX_REPOS ?? 0) || Infinity
/** Comma-separated owner/name filter — restrict analysis to specific repos. */
export const GOVC_REPOS = process.env.GOVC_REPOS?.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
export const ghKey = (gh: { owner: string; name: string }) => `${gh.owner}/${gh.name}`.toLowerCase()

export const ghRepoOf = (url: string | null) => {
  const m = url && /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)/i.exec(url)
  return m ? { owner: m[1], name: m[2].replace(/\.git$/, '') } : null
}

async function sh(cmd: string, args: string[], cwd: string, timeout = 120_000, env?: Record<string, string>): Promise<{ out: string; err: string; ok: boolean }> {
  try {
    const { stdout, stderr } = await execP(cmd, args, { cwd, timeout, maxBuffer: 128 * 1024 * 1024, env: { ...process.env, ...env } })
    return { out: String(stdout), err: String(stderr), ok: true }
  } catch (e) {
    const x = e as { stdout?: string | Buffer; stderr?: string | Buffer }
    return { out: String(x.stdout ?? ''), err: String(x.stderr ?? e), ok: false }
  }
}

let govcBin: string | null | undefined
export async function govcBinary(): Promise<string | null> {
  if (govcBin !== undefined) return govcBin
  if ((await sh('which', ['govulncheck'], '.')).ok) return (govcBin = 'govulncheck')
  if (!(await sh('go', ['version'], '.')).ok) return (govcBin = null)
  const gobin = (await sh('go', ['env', 'GOBIN'], '.')).out.trim() || `${(await sh('go', ['env', 'GOPATH'], '.')).out.trim()}/bin`
  const bin = `${gobin}/govulncheck`
  if (await stat(bin).then(() => true, () => false)) return (govcBin = bin)
  log('govulncheck not found — running `go install golang.org/x/vuln/cmd/govulncheck@latest`')
  if ((await sh('go', ['install', 'golang.org/x/vuln/cmd/govulncheck@latest'], '.', 600_000)).ok && (await stat(bin).then(() => true, () => false))) return (govcBin = bin)
  return (govcBin = null)
}

async function goModDirs(dir: string, depth = 0): Promise<string[]> {
  if (depth > 6) return []
  const ents = await readdir(dir, { withFileTypes: true }).catch(() => null)
  if (!ents) return []
  const out = ents.some((e) => e.isFile() && e.name === 'go.mod') ? [dir] : []
  for (const e of ents) {
    if (!e.isDirectory() || e.name === 'vendor' || e.name === 'node_modules' || e.name.startsWith('.')) continue
    out.push(...(await goModDirs(resolve(dir, e.name), depth + 1)))
  }
  return out
}

interface GvFrame {
  module?: string
  package?: string
  function?: string
}

// govulncheck -json emits a stream of pretty-printed messages, each starting with
// `{` at column 0. A finding's trace depth is the evidence tier: module-only frame
// (required, not imported) < package frame (imported, symbols not called) <
// function frames (call path exists — trace[0] is the vulnerable symbol, trace[-1]
// the callsite). Deepest tier per OSV wins.
function parseGovc(out: string): Map<string, { v: 'called' | 'not-called'; t: string | null; rank: number; m: string | null; v2: string | null }> {
  const per = new Map<string, { v: 'called' | 'not-called'; t: string | null; rank: number; m: string | null; v2: string | null }>()
  for (const chunk of out.split(/^\{/m)) {
    if (!chunk.trim()) continue
    let msg: { finding?: { osv?: string; trace?: GvFrame[] } }
    try {
      msg = JSON.parse(`{${chunk}`)
    } catch {
      continue
    }
    const osv = msg.finding?.osv
    if (!osv) continue
    const frames = msg.finding?.trace ?? []
    const rank = frames.some((f) => f.function) ? 2 : frames.some((f) => f.package) ? 1 : 0
    const prev = per.get(osv)
    if (prev && prev.rank >= rank) continue
    const funcs = frames.filter((f) => f.function)
    const trace = funcs.length
      ? `${funcs[0].package}.${funcs[0].function} ← ${funcs[funcs.length - 1].package}.${funcs[funcs.length - 1].function}`
      : rank === 1
        ? 'vulnerable package imported; no call path found'
        : 'module required; vulnerable packages not imported'
    per.set(osv, { v: rank === 2 ? 'called' : 'not-called', t: trace, rank, m: frames[0]?.module ?? null, v2: (frames[0] as { version?: string } | undefined)?.version ?? null })
  }
  return per
}

/** Reachability verdict per OSV id. m/v2 = the vulnerable module path + version
 * govulncheck resolved from the repo's go.mod (used to emit new findings). */
export type ReachVerdicts = Map<string, { v: Reachability; t: string | null; m: string | null; v2: string | null }>

// Shallow-clone (or refresh) the repo, run govulncheck per go.mod directory, return
// per-OSV verdicts. null = could not analyze (clone or every module run failed).
export async function govcRepo(bin: string, gh: { owner: string; name: string }, url: string): Promise<ReachVerdicts | null> {
  const key = `${gh.owner}/${gh.name}`.toLowerCase()
  const dir = resolve(CLONES_DIR, key.replace('/', '__'))
  await mkdir(CLONES_DIR, { recursive: true })
  if (await stat(resolve(dir, '.git')).then(() => true, () => false)) {
    await sh('git', ['fetch', '--depth=1', 'origin'], dir, 240_000)
    await sh('git', ['reset', '--hard', 'FETCH_HEAD'], dir)
  } else {
    await rm(dir, { recursive: true, force: true }).catch(() => {})
    if (!(await sh('git', ['clone', '--depth=1', url, dir], CLONES_DIR, 360_000)).ok) {
      log(`govulncheck: clone failed for ${key}`)
      return null
    }
  }
  const head = await sh('git', ['rev-parse', 'HEAD'], dir)
  if (!head.ok) return null
  const ck = `govc2:${key}@${head.out.trim()}`
  const hit = await cacheGet<{ v: Record<string, { c: boolean; t: string | null; m: string | null; v2: string | null }> }>(ck, GOVC_TTL_MS)
  if (hit !== undefined) return hit ? new Map(Object.entries(hit.v).map(([k, x]) => [k, { v: x.c ? 'called' : 'not-called', t: x.t, m: x.m, v2: x.v2 }])) : null
  const mods = await goModDirs(dir)
  if (!mods.length) {
    log(`govulncheck: no go.mod in ${key}`)
    return null
  }
  const merged = new Map<string, { v: Reachability; t: string | null; rank: number; m: string | null; v2: string | null }>()
  let ok = 0
  for (const m of mods) {
    const run = await sh(bin, ['-json', '-mode=source', './...'], m, 420_000, { GOFLAGS: '-mod=mod' })
    if (!run.ok || !run.out.startsWith('{')) {
      log(`govulncheck failed in ${key}:${m.slice(dir.length) || '/'} — ${run.err.trim().split('\n')[0]?.slice(0, 160)}`)
      continue
    }
    ok++
    for (const [osv, g] of parseGovc(run.out)) {
      const prev = merged.get(osv)
      if (!prev || g.rank > prev.rank) merged.set(osv, g)
    }
  }
  if (!ok) return null
  const out: ReachVerdicts = new Map([...merged].map(([k, x]) => [k, { v: x.v, t: x.t, m: x.m, v2: x.v2 }]))
  await cacheSet(ck, { v: Object.fromEntries([...merged].map(([k, x]) => [k, { c: x.v === 'called', t: x.t, m: x.m, v2: x.v2 }])) })
  return out
}
