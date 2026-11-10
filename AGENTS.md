# Stellar PG Aegis

Security posture, vulnerability exposure and disclosure routing for Stellar public goods.
See `Specification.md` for the full product/technical spec.

## Layout

- `Specification.md` — product + technical specification (source of truth for API contract, FR numbers).
- `frontend/` — React 19 + TypeScript + Vite 6 + Tailwind CSS v4 dashboard.
- Backend — not yet implemented (planned: FastAPI + PostgreSQL, see spec §8).

## Frontend

Run from `frontend/`:

- Install: `npm install`
- Dev server: `npm run dev` (http://localhost:5173)
- Lint: `npm run lint`
- Typecheck + production build: `npm run build`
- Data snapshot: `GITHUB_TOKEN=$(gh auth token) PG_ATLAS_API=<url> npm run data:refresh`

Verification before finishing a change: `npm run lint && npm run build`.

### Data layer

- `src/api/types.ts` — response types mirroring spec FR10. Keep in sync with `Specification.md`.
  `null` always means "not collected" — never fabricate values. `criticality_score` is an
  integer count of dependents, `adoption_score` is 0–100 (both PG Atlas semantics).
- `src/api/client.ts` — `AegisApi` interface + HTTP client (`/v1/*`) for the future backend.
- `src/api/snapshotClient.ts` — serves `public/data/snapshot.json`.
- `src/api/index.ts` — `VITE_API_BASE_URL` set → live HTTP client; otherwise the snapshot.
- `scripts/build-snapshot.ts` — snapshot builder; run `npm run data:refresh`.
  Sources: PG Atlas API (`PG_ATLAS_API`, default `https://api.pgatlas.xyz`), OSV `/v1/querybatch`
  + `/v1/vulns`, CISA KEV, FIRST EPSS, GitHub GraphQL/REST (`GITHUB_TOKEN`), OpenSSF Scorecard,
  security.txt. Respects PG Atlas 100 req/min limit, honors `Retry-After`, and disk-caches
  in `scripts/.cache/` (PG responses 24h, GitHub/Scorecard 72h) so refreshes resume.
  `GH_MAX_REPOS=<n>` caps GitHub enrichment per run (repos with findings first, then by stars);
  unenriched repos show as "unknown" in the UI.
- React Query hooks (`useProjects`, `useVulnExposure`, ...) live in `src/api/index.ts`.
- Priority weights (spec FR5) live in `src/lib/priority.ts`; severity falls back to the
  advisory label when no CVSS v3 score is computable (`unknown` severity is possible).

### Conventions

- Tailwind v4 with custom utilities (`card`, `input`, `btn-primary`, `btn-ghost`, `th`, `td`) defined via `@utility` in `src/index.css`.
- Shared UI primitives in `src/components/ui.tsx`; pages are lazy-loaded in `src/App.tsx`.
- Recharts animations are disabled (`isAnimationActive={false}`) so charts render reliably (incl. headless screenshots).
- In `useEffect`, never implicitly return the result of `window.scrollTo(...)` — Chrome returns a Promise, which React treats as an invalid cleanup.

### Known audit note

`npm audit` reports a moderate `minimatch` advisory (GHSA-g3hv-75wg-m249) via `typescript-eslint` (dev-only, lint tooling).
The fix requires minimatch 11.x, which `typescript-eslint` does not yet accept; revisit when it updates.
