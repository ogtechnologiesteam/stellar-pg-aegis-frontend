// Shared disk cache so re-runs reuse fetched responses (PG Atlas GETs, GitHub/Scorecard
// lookups, govulncheck verdicts). Imported by build-snapshot.ts and annotate-reachability.ts.
import { createHash } from 'node:crypto'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const log = (...a: unknown[]) => console.error('[snapshot]', ...a)

export const CACHE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '.cache')
export const cachePath = (url: string) => resolve(CACHE_DIR, `${createHash('sha1').update(url).digest('hex')}.json`)

export async function cacheGet<T>(url: string, ttl: number): Promise<T | null | undefined> {
  try {
    const file = cachePath(url)
    if (Date.now() - (await stat(file)).mtimeMs < ttl) return JSON.parse(await readFile(file, 'utf8')) as T | null
  } catch {
    /* cache miss */
  }
  return undefined
}

export const cacheSet = (url: string, body: unknown) => writeFile(cachePath(url), JSON.stringify(body ?? null))
