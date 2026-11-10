# Stellar PG Aegis — Specification

> Security posture, vulnerability exposure, and disclosure routing for Stellar public goods.

| Field        | Value                                   |
| ------------ | --------------------------------------- |
| Status       | Draft v0.1                              |
| Date         | 2026-11-10                              |
| Ecosystem    | Stellar / Soroban (SCF Public Goods)    |
| Upstream     | PG Atlas (`api.pgatlas.xyz`), OSV.dev, GitHub, OpenSSF Scorecard |

---

## 1. Background and Problem Statement

### 1.1 Current landscape

The [SCF Public Goods Maintenance Working Group](https://scf-public-goods-maintenance.github.io/) runs the
Public Goods Award and operates **PG Atlas**, the program's metrics backbone. Based on the published docs:

| Capability                                   | PG Atlas today | PG Atlas roadmap |
| -------------------------------------------- | -------------- | ---------------- |
| Dependency graph (SBOM + registry inference) | Yes            | —                |
| Criticality, adoption, pony factor           | Yes            | —                |
| Activity status (`live`, `in-dev`, `discontinued`, `non-responsive`) | Yes | Granular scoring |
| Issue / PR responsiveness, backlog           | No             | Proposed (D3, backend issue #80; "GitHub API data" in Extensibility) |
| CVE / advisory feed integration              | No             | "Under consideration" (Security indicators) |
| Per-release blast radius                     | No             | "Under consideration" (Versioned dependency edges) |
| SECURITY.md / disclosure policy detection    | No             | Not mentioned    |
| Bug-specific tracking                        | No             | Not mentioned    |

Related ecosystem projects:

- **Stellar Security Portal** (`stellarsecurityportal.com`, Inferara) — a curated, manually reviewed
  knowledge base of **audit reports and audit findings** for Soroban protocols (~954 findings, 66 reports
  as of Oct 2026). It covers *audited smart-contract findings*, not dependency CVEs or disclosure routing.
- **Scout** (CoinFabrik) — static analysis for Soroban contracts.
- **Stellar bug bounty programs** (HackerOne / Immunefi) — cover Stellar Development Foundation assets,
  not every SCF public good.

### 1.2 Gap

No system today answers, for the ~600 active SCF projects:

1. *Which public goods currently ship a dependency with a known vulnerability, and is it fixed upstream?*
2. *If package X gets a CVE today, which Stellar public goods are exposed, directly or transitively, and how critical are they?*
3. *How do I privately report a vulnerability to project Y?* (SECURITY.md, GitHub Private Vulnerability Reporting, bounty program, email)
4. *Which critical public goods have no disclosure policy at all?*
5. *Is the maintainer responsive to security-relevant issues?*

### 1.3 Value proposition

Aegis is **not** a new scanner or a new vulnerability database. It is a Stellar-aware orchestration layer
that joins existing data:

```
PG Atlas (graph, criticality, SBOMs)  +  OSV.dev (vulns)  +  GitHub (policy, advisories, issues)
                                   ──► prioritized exposure + disclosure routing + remediation guidance
```

Differentiators vs. generic tools (Dependency-Track, Dependabot, Snyk):

- **Ecosystem-weighted prioritization** — severity × PG Atlas criticality × pony factor.
- **Ecosystem-wide blast radius** — reverse traversal over the cross-project graph, which per-repo tools cannot do.
- **Disclosure routing** — one canonical answer to "how do I report to this project".
- **Hygiene signals** — missing policy, PVR disabled, stale advisories, unpatched-but-fixable deps.
- **Feeds back into PG Atlas** — exposes signals PG Atlas has listed as roadmap items, instead of competing with it.

---

## 2. Goals and Non-Goals

### 2.1 Goals (v1)

- **G1** Map known vulnerabilities (OSV) onto the dependencies of every SCF public good with an SBOM or inferred graph.
- **G2** Compute transitive exposure (blast radius) and rank findings by ecosystem impact.
- **G3** Discover and normalize each project's vulnerability disclosure channel(s).
- **G4** Score project security hygiene (policy present, PVR enabled, advisories published, Scorecard checks).
- **G5** Provide remediation guidance (fixed version, upgrade path, workaround link) per finding.
- **G6** Public read API + dashboard; notifications for maintainers who opt in.

### 2.2 Non-Goals

- **NG1** Hosting or receiving undisclosed vulnerability reports. Aegis *routes* reporters; it never stores embargoed details.
- **NG2** Publishing new vulnerability data or exploit details beyond what is already public in OSV/GHSA.
- **NG3** Replacing the Stellar Security Portal's audit-findings knowledge base (link to it instead).
- **NG4** Smart-contract static analysis (Scout's domain).
- **NG5** Mirroring every GitHub issue. Issue data is consumed only as aggregate signals.
- **NG6** Producing a single "security score" used for funding decisions without maintainer review
  (consistent with PG Atlas #80 "profiles, not a score").

---

## 3. Users and Use Cases

| Persona                 | Primary use case |
| ----------------------- | ---------------- |
| PG maintainer           | See vulnerable deps in my repos, fixed versions, and what downstream projects are affected by my release. |
| Downstream integrator   | "Is the SDK / library I depend on currently vulnerable? Is a patch out?" |
| Security researcher     | Find the correct private disclosure channel for a project in one lookup. |
| SCF / Working Group     | Ecosystem-wide risk view; identify critical PGs lacking a disclosure policy; input to award reviews. |
| PG Atlas                | Consume Aegis signals as additional metric columns. |

### Key user stories

- **US1** As a researcher, I enter a repo/project name and get its disclosure channels ranked by preference, with source and last-verified date.
- **US2** As a maintainer, I see open findings for my repos with: advisory ID, severity, affected path (direct/transitive), fixed version.
- **US3** As the WG, when a new advisory hits OSV for a popular package, I see within 24h which SCF projects are exposed, ordered by criticality.
- **US4** As the WG, I can list all public goods with criticality above a threshold and no SECURITY.md / PVR.
- **US5** As a maintainer, I can opt in to receive notifications (GitHub issue, email, webhook) about new findings — never auto-filed publicly without opt-in.

---

## 4. Data Sources

### 4.1 PG Atlas (primary inventory)

Public, unauthenticated, rate-limited REST API (`https://api.pgatlas.xyz`, OpenAPI at `/openapi.json`,
TypeScript SDK `pg-atlas-ts-sdk`).

| Endpoint | Used for |
| -------- | -------- |
| `GET /projects?project_type=public-good` | Project inventory, `criticality_score`, `adoption_score`, `pony_factor`, `activity_status`, `git_owner_url` |
| `GET /projects/{id}/repos` | Repo inventory per project |
| `GET /repos/{id}` | Releases (PURL + version), dependency edge counts |
| `GET /repos/{id}/depends-on` | Direct deps: `canonical_id`, `vertex_type`, `version_range`, `confidence` (`verified-sbom` / `inferred-shadow`) |
| `GET /repos/{id}/has-dependents` | Reverse edges for blast radius |
| `GET /ingest/sbom`, `GET /ingest/sbom/{id}` | Raw **SPDX 2.3** SBOM artifacts (exact package versions + PURLs where available) |

**Do existing SBOMs help? Yes — they are the highest-value input.**

- PG Atlas SBOMs are **SPDX 2.3** produced from the GitHub Dependency Graph API and submitted via
  `pg-atlas-sbom-action` with OIDC-verified repo identity.
- They contain PURLs (`externalRefs` of type `purl`), which map directly to OSV queries.
- Caveats that the design must handle:
  - Coverage is opt-in; many repos only have `inferred-shadow` edges from registry crawls.
  - Manifest-derived entries may carry **version ranges** rather than resolved versions (no lockfile).
  - Dependency Graph SBOMs may be shallow (direct deps only) depending on ecosystem/lockfile support.
  - SBOM content is identity-verified but not content-verified (per PG Atlas trust model).

### 4.2 Vulnerability intelligence

| Source | Access | Role |
| ------ | ------ | ---- |
| **OSV.dev** | `POST /v1/querybatch`, `POST /v1/query`, `GET /v1/vulns/{id}`; bulk GCS exports per ecosystem; no auth | **Primary.** Aggregates GHSA, PyPI, npm, Go, RustSec, Packagist, Pub, Maven, NuGet, etc. PURL + version native. |
| GitHub Advisory DB (global) | `GET /advisories` (REST) / GraphQL `securityVulnerabilities` | Secondary / cross-check; included in OSV. |
| GitHub repo advisories | `GET /repos/{o}/{r}/security-advisories` | Advisories *published by the project itself* (hygiene + project's own vulns). |
| deps.dev | Already used by PG Atlas; exposes advisory keys per version | Optional cross-check and transitive resolution. |
| NVD | CVE metadata (CVSS, CWE) | Enrichment only. |
| CISA KEV, FIRST EPSS | Public feeds | Exploitation likelihood for prioritization. |

### 4.3 Disclosure and hygiene

| Source | Access | Signal |
| ------ | ------ | ------ |
| SECURITY.md | GitHub contents API; check `/SECURITY.md`, `/.github/SECURITY.md`, `/docs/SECURITY.md`, and the org-level `.github` repo fallback | Presence, contacts (emails, URLs), supported versions, SLA statements |
| Private Vulnerability Reporting | `GET /repos/{o}/{r}/private-vulnerability-reporting` | PVR enabled flag (preferred channel when true) |
| `security.txt` (RFC 9116) | `https://<project website>/.well-known/security.txt` | Contact for project websites/services |
| Bug bounty programs | Curated list (HackerOne, Immunefi, SDF program scope) | Bounty coverage |
| OpenSSF Scorecard | `api.securityscorecards.dev/projects/github.com/{o}/{r}` | `Security-Policy`, `Vulnerabilities`, `Dependency-Update-Tool`, `Branch-Protection`, `Signed-Releases`, etc. |
| Stellar Security Portal | Link-out by protocol name | Audit reports/findings for the project, if any |

### 4.4 Issue / bug signals (aggregate only)

GitHub REST/GraphQL, aligned with PG Atlas #80 definitions to avoid divergent metrics:

- Count and median age of open issues labeled `security`, `vulnerability`, `bug` (label sets configurable).
- Maintainer first-response time on those issues (trailing 90 days, 7-day threshold).
- Dependabot/Renovate PR latency (time-to-merge of dependency-update PRs) — a strong patch-velocity proxy.

Dependabot *alerts* for a repo require admin access and are **not** used unless the maintainer installs the
Aegis GitHub App (§7.3).

---

## 5. Functional Requirements

### FR1 Inventory sync
- FR1.1 Nightly sync of public-good projects, repos, releases, and edges from PG Atlas.
- FR1.2 Fetch new SBOM artifacts incrementally (track last seen submission id / content hash).
- FR1.3 Parse SPDX 2.3: packages, versions, PURLs, relationships (`DEPENDS_ON`, `CONTAINS`, nested).

### FR2 Version resolution
- FR2.1 Prefer exact versions from SBOM. Mark each component `resolution = exact | range | unknown`.
- FR2.2 For ranges, resolve to the latest version satisfying the range as a *best-case* and the lowest as a
  *worst-case*; report findings with `confidence = possible` when only the worst case is affected.
- FR2.3 Inferred (`inferred-shadow`) edges produce findings with `confidence = inferred`.

### FR3 Vulnerability matching
- FR3.1 Batch-query OSV by PURL+version (`/v1/querybatch`, ≤1000 queries/request), then hydrate with `/v1/vulns/{id}`.
- FR3.2 Optionally run from OSV bulk exports for full re-scans to avoid API limits.
- FR3.3 Store aliases (CVE, GHSA, RUSTSEC, PYSEC…) and dedupe to a single finding per (component, vuln group).
- FR3.4 Re-match on: new SBOM, new release, new/modified OSV record (poll `modified` timestamps hourly).
- FR3.5 Honor withdrawn advisories (`withdrawn` field) by auto-closing findings.

### FR4 Exposure and blast radius
- FR4.1 For each finding on repo R, traverse `has-dependents` up to depth N (default 5) to list exposed downstream repos/projects.
- FR4.2 For each external package with an advisory, list all SCF repos depending on it (direct + transitive).
- FR4.3 Label exposure as `direct`, `transitive(depth)`.

### FR5 Prioritization
Priority score (0–100), documented and transparent:

```
priority = w1·severity_norm(CVSS/OSV severity)
         + w2·criticality_norm(PG Atlas)
         + w3·exploitability(KEV ∈ {0,1}, EPSS)
         + w4·exposure_depth_factor (direct > transitive)
         + w5·fix_available (fix exists ⇒ higher actionability)
         − w6·confidence_penalty(possible / inferred)
```
Default weights published in config; per-finding breakdown returned by the API.

### FR6 Disclosure routing
- FR6.1 Detect SECURITY.md in standard locations incl. org-level fallback; record source URL and commit SHA.
- FR6.2 Extract contacts: emails, URLs (HackerOne/Immunefi/forms), PGP key references, "use GitHub PVR" instructions, supported-versions table, stated response SLA.
- FR6.3 Extraction is rule-based first (regex + markdown section parsing); an optional LLM pass may suggest structure but results are flagged `extracted_by = llm` and never override rule-based output.
- FR6.4 Rank channels: PVR enabled > SECURITY.md designated channel > bounty program > security.txt > maintainer contact (last resort, flagged).
- FR6.5 Never recommend public issues for vulnerability reports.
- FR6.6 Re-verify weekly; show `last_verified_at`.

### FR7 Hygiene profile (per repo and aggregated per project)
Boolean/numeric signals, *profiles not a score*:
- has_security_policy, pvr_enabled, has_security_txt, bounty_covered
- published_advisories_count, last_advisory_at
- open_findings_by_severity, oldest_unpatched_fixable_age_days
- dependency_update_tool (Scorecard), scorecard_overall, selected Scorecard checks
- security_issue_response_median_hours (§4.4)
- audit_reports_on_security_portal (link/count)

### FR8 Remediation guidance
- FR8.1 For each finding: fixed version(s) from OSV `affected.ranges.events.fixed`, minimal upgrade target, upstream advisory and patch commit links.
- FR8.2 Ecosystem-specific upgrade hint (e.g., `cargo update -p <crate> --precise <v>`, `npm install <pkg>@<v>`, `pip install '<pkg>>=<v>'`, `dart pub upgrade <pkg>`, `composer require <pkg>:^<v>`).
- FR8.3 If no fix: surface workarounds from advisory text and mark `no_fix_available`.
- FR8.4 Generic playbooks: "how to publish a GitHub Security Advisory", "how to enable PVR", "SECURITY.md template" (Stellar-specific template with links to SDF bounty scope where applicable).

### FR9 Notifications (opt-in only)
- FR9.1 Channels: email, webhook, GitHub issue (only in repos that opted in via App or config file `.github/aegis.yml`).
- FR9.2 Digest mode (daily/weekly) and immediate mode for `critical`/KEV.
- FR9.3 Default for non-opted-in projects: no outbound contact. Findings remain visible only via public dashboard/API (they are derived from already-public data).

### FR10 Public API (read-only)
| Endpoint | Description |
| -------- | ----------- |
| `GET /v1/projects` | Projects with hygiene summary + open findings counts. Query: `search`, `activity_status`, `has_policy`, `sort` (`priority`\|`criticality`\|`name`\|`findings`), `limit`, `offset` |
| `GET /v1/projects/{canonical_id}` | Full profile, disclosure channels, findings |
| `GET /v1/findings` | Ecosystem-wide findings ordered by priority. Query: `limit`, `offset` |
| `GET /v1/repos/{canonical_id}/findings` | Findings with priority breakdown, filters: severity, confidence, status |
| `GET /v1/vulns` | Advisories affecting ≥1 public good. Query: `search`, `severity`, `ecosystem`, `limit`, `offset` |
| `GET /v1/vulns/{id}/exposure` | Advisory detail + all SCF repos/projects exposed to it (blast radius) |
| `GET /v1/packages/{purl}/exposure` | Exposure for an external package |
| `GET /v1/disclosure?q=` | Disclosure lookup by project / repo name |
| `GET /v1/disclosure/{canonical_id}` | Ranked disclosure channels |
| `GET /v1/ecosystem/summary` | Aggregate stats, policy coverage, weekly trend |
| `GET /v1/export/{dataset}.{csv,json}` | Bulk exports |

Use `canonical_id` identical to PG Atlas to make joins trivial. OpenAPI spec published; generated TS SDK.
The response shapes the frontend expects are defined in `frontend/src/api/types.ts`.

### FR11 Dashboard
- Ecosystem overview: policy coverage %, open findings by severity, critical PGs with exposure.
- Advisory view: blast radius graph (Cytoscape.js, consistent with PG Atlas dashboard).
- Project page: disclosure card (top channel + copy button), hygiene profile, findings table, remediation.
- "Report a vulnerability" lookup: search box → disclosure card.

### FR12 PG Atlas integration
- Publish per-repo/project signals in a format PG Atlas can ingest as metric columns
  (`has_security_policy`, `pvr_enabled`, `open_vuln_count_{severity}`, `max_finding_priority`).
- Propose upstream via PG Atlas extension pattern ("Adding New Metrics") once validated.

---

## 6. Non-Functional Requirements

| Area | Requirement |
| ---- | ----------- |
| Freshness | New OSV advisory → exposure computed within 24h (target 1h). New SBOM → findings within 2h. |
| Scale | ~1k projects, ~5k repos, ~20k external repos, ~50k edges, ~10⁵ components. |
| Rate limits | Respect PG Atlas per-IP limits (cache, incremental sync); GitHub App installation tokens; OSV batch + bulk exports. |
| Availability | 99% for read API; ingestion may degrade without affecting reads. |
| Reproducibility | Every finding stores input snapshot ids (SBOM hash, OSV record `modified`, PG Atlas sync id). |
| Transparency | Scoring weights, label sets, and extraction rules are versioned in the repo. |
| Licensing | Respect OSV data licenses (per-source; mostly CC-BY 4.0) and attribute in UI/API. |

---

## 7. Security, Privacy, and Ethics

### 7.1 Responsible disclosure posture
- Aegis surfaces **only already-public** vulnerability data (OSV/GHSA/NVD).
- No storage of embargoed reports, no intake form for vulnerability details.
- Repo-published advisories in `draft`/`triage` state are never fetched or displayed.
- For `critical` findings on high-criticality PGs, an optional 72h "maintainer-first" delay before
  dashboard prominence (configurable; data is public regardless, this only controls highlighting).

### 7.2 Data minimization
- Store contributor/maintainer data only as hashes or as already-public SECURITY.md contacts.
- Do not scrape personal emails from commits for routing.

### 7.3 GitHub App (optional, opt-in)
- Permissions: `metadata:read`, `contents:read`, `issues:write` (only for opted-in notifications),
  `vulnerability_alerts:read` (Dependabot alerts — only if maintainer grants).
- Dependabot alert data from private sources shown only to authenticated maintainers of that repo.

### 7.4 Platform security
- Read API unauthenticated; admin endpoints behind OIDC/SSO.
- Secrets in managed secret store; least-privilege tokens; pinned actions by full commit SHA.
- Aegis itself publishes a SECURITY.md, enables PVR, and submits its SBOM to PG Atlas.

---

## 8. Architecture

```
                ┌──────────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────┐
  Sources       │  PG Atlas API│  │  OSV.dev   │  │ GitHub API / │  │ Scorecard,   │
                │  (graph,SBOM)│  │ (API+bulk) │  │ App (policy, │  │ KEV, EPSS,   │
                └──────┬───────┘  └─────┬──────┘  │ advisories,  │  │ security.txt │
                       │                │         │ issues)      │  └──────┬───────┘
                       │                │         └──────┬───────┘         │
                ┌──────▼────────────────▼────────────────▼─────────────────▼──────┐
  Ingestion     │  Workers (job queue): inventory-sync, sbom-parse, osv-match,    │
                │  osv-delta-poll, policy-crawl, hygiene-collect, enrich          │
                └──────────────────────────────┬──────────────────────────────────┘
                                               │
                ┌──────────────────────────────▼──────────────────────────────────┐
  Storage       │ PostgreSQL: projects, repos, components, edges (mirror),        │
                │ vulns, findings, exposures, disclosure_channels, hygiene, runs  │
                │ Object store: raw SBOMs, SECURITY.md snapshots                  │
                └──────────────────────────────┬──────────────────────────────────┘
                                               │
                ┌──────────────────────────────▼──────────────────────────────────┐
  Compute       │ Blast radius (NetworkX / recursive CTE), priority scoring,      │
                │ remediation hints, hygiene aggregation                          │
                └───────────────┬───────────────────────────────┬─────────────────┘
                                │                               │
                       ┌────────▼────────┐             ┌────────▼────────┐
  Delivery             │ FastAPI read API │             │ Notifier (opt-in)│
                       │ + OpenAPI + SDK  │             │ email/webhook/GH │
                       └────────┬────────┘             └─────────────────┘
                       ┌────────▼────────┐
                       │ React dashboard │
                       └─────────────────┘
```

### 8.1 Technology choices
Aligned with PG Atlas to ease contribution and potential upstreaming:

- Python 3.12+, FastAPI, SQLAlchemy/Alembic, PostgreSQL 16
- Procrastinate (Postgres-backed job queue, as used by PG Atlas) or equivalent
- NetworkX for graph traversal (recursive CTEs as fallback)
- React + TypeScript + Cytoscape.js dashboard
- `osv-scanner` / OSV API client; `spdx-tools` for SPDX parsing; `packageurl-python` for PURLs
- GitHub Actions for scheduled workflows; container deploy

### 8.2 Core data model

```
project(canonical_id PK, display_name, project_type, activity_status,
        criticality_score, adoption_score, pony_factor, synced_at)
repo(canonical_id PK, project_id FK, git_url, default_branch, synced_at)
component(id PK, purl, ecosystem, name, version, resolution ENUM(exact,range,unknown), version_range)
repo_component(repo_id FK, component_id FK, source ENUM(verified-sbom,inferred-shadow),
               direct BOOL, sbom_submission_id)
vuln(id PK, aliases TEXT[], summary, severity_cvss, severity_label, published, modified,
     withdrawn, kev BOOL, epss FLOAT, references JSONB, raw JSONB)
vuln_affected(vuln_id FK, ecosystem, package, ranges JSONB, fixed_versions TEXT[])
finding(id PK, repo_id FK, component_id FK, vuln_id FK, status ENUM(open,fixed,withdrawn,ignored),
        confidence ENUM(confirmed,possible,inferred), priority, priority_breakdown JSONB,
        first_seen, last_seen, closed_at, remediation JSONB)
exposure(vuln_id FK, repo_id FK, depth INT, via_repo_id FK)
disclosure_channel(id PK, repo_id FK, kind ENUM(pvr,email,url,bounty,security_txt,form,other),
                   value, rank, source_url, source_sha, extracted_by ENUM(rule,llm,manual),
                   last_verified_at)
hygiene(repo_id PK, has_security_policy, pvr_enabled, has_security_txt, bounty_covered,
        published_advisories_count, last_advisory_at, scorecard JSONB,
        security_issue_response_median_h, collected_at)
run(id PK, kind, started_at, finished_at, inputs JSONB, stats JSONB, status)
```

### 8.3 Scheduled workflows

| Workflow | Cadence | Notes |
| -------- | ------- | ----- |
| `inventory-sync` | Daily | PG Atlas projects/repos/edges; incremental by `updated_at` |
| `sbom-sync` | Hourly | New SBOM submissions → parse → `osv-match` |
| `osv-delta-poll` | Hourly | OSV records modified since last poll → re-match affected components |
| `osv-full-rescan` | Weekly | From bulk exports |
| `policy-crawl` | Weekly + on push (App) | SECURITY.md, PVR, security.txt |
| `hygiene-collect` | Weekly | Scorecard, advisories, issue signals |
| `notify` | Hourly / daily digest | Opt-in only |

---

## 9. Phased Delivery

| Phase | Scope | Exit criteria |
| ----- | ----- | ------------- |
| **P0 – Feasibility (2–3 wks)** | Pull PG Atlas inventory + SBOMs; run OSV batch on all `verified-sbom` repos; crawl SECURITY.md/PVR for all public goods. Produce a one-off report. | Report shared with WG: coverage %, findings counts, policy coverage. Go/no-go. |
| **P1 – MVP** | FR1–FR3, FR6, FR7 (policy subset), FR10 core endpoints, minimal dashboard (disclosure lookup + findings table). | Public API live; disclosure lookup for 100% of public goods; findings for all SBOM repos. |
| **P2 – Exposure & prioritization** | FR4, FR5, FR8, advisory blast-radius view, KEV/EPSS enrichment. | US3 met within 24h SLA. |
| **P3 – Maintainer loop** | GitHub App, FR9 opt-in notifications, Dependabot alerts (opt-in), issue signals (§4.4). | ≥10 PGs opted in; median time-to-fix measured. |
| **P4 – Upstreaming** | FR12: contribute selected signals to PG Atlas as metrics; SECURITY.md template + playbooks adopted by WG. | Merged PG Atlas PR or documented integration. |

---

## 10. Success Metrics

- % of public goods with a discoverable disclosure channel (baseline in P0; target +30pp within 6 months via outreach + templates).
- % of public goods with PVR enabled.
- Median age of open, fixable findings in high-criticality PGs (target decreasing quarter over quarter).
- Time from OSV publication to Aegis exposure report.
- Number of maintainers opted in to notifications.
- SBOM coverage uplift (Aegis findings as an incentive for submitting SBOMs to PG Atlas).

---

## 11. Risks and Mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Low SBOM coverage / range-only versions → false positives | Confidence levels (FR2); show `possible`/`inferred` separately; encourage lockfile-backed SBOMs. |
| Perceived "naming and shaming" | Profiles not scores; maintainer-first highlighting window; opt-in notifications; framing as support. |
| Duplicating PG Atlas or Security Portal | Reuse PG Atlas `canonical_id` and API; link-out to Security Portal; upstream signals (P4). Engage WG before P1. |
| SECURITY.md free-form text extraction errors | Rule-based extraction, source snapshot + SHA, manual override, maintainer correction via `.github/aegis.yml`. |
| API rate limits | Caching, incremental syncs, OSV bulk exports, GitHub App tokens. |
| Advisory data licensing | Per-source attribution; store license per record. |
| Inaccurate data impacting award decisions | Explicit disclaimer; WG consumes signals only after maintainer review period. |

---

## 12. Open Questions

1. Should Aegis be a standalone service or a PG Atlas module from day one? (Recommend: standalone P0–P2, upstream P4.)
2. Does the WG want security hygiene to influence Public Goods Award scoring, and if so with what review process?
3. Can PG Atlas expose resolved lockfile versions or a bulk SBOM export endpoint to reduce per-artifact fetching?
4. Which Stellar bug bounty scopes (SDF HackerOne / Immunefi) cover which SCF public goods? Needs a curated mapping.
5. Should Soroban contract-level findings from the Stellar Security Portal be linked per project via a shared identifier?
6. Funding path: submit Aegis as a Public Goods Award proposal or as a PG Atlas contribution?

---

## 13. References

- SCF Public Goods Maintenance WG — https://scf-public-goods-maintenance.github.io/
- PG Atlas architecture — https://scf-public-goods-maintenance.github.io/pg-atlas/
  - Ingestion (SPDX 2.3 SBOM action, OIDC trust model) — `/pg-atlas/ingestion/`
  - API Layer — `/pg-atlas/api/`
  - Extensibility (Future: CVE feeds, GitHub issue/PR stats, versioned edges) — `/pg-atlas/extensibility/`
- PG Atlas dashboard — https://www.pgatlas.xyz/ ; API — https://api.pgatlas.xyz
- PG Atlas maintenance signals proposal — `SCF-Public-Goods-Maintenance/pg-atlas-backend#80`
- Stellar Security Portal — https://stellarsecurityportal.com/
- OSV — https://osv.dev/ ; schema — https://ossf.github.io/osv-schema/
- GitHub Advisory Database / REST security advisories API — https://docs.github.com/en/rest/security-advisories
- OpenSSF Scorecard — https://scorecard.dev/
- RFC 9116 `security.txt`
- OWASP Dependency-Track (reference design for SBOM-based vuln tracking) — https://dependencytrack.org/
