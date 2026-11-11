export interface GlossaryTerm {
  slug: string
  term: string
  short: string
  details: string[]
  related: string[]
}

export const GLOSSARY: GlossaryTerm[] = [
  {
    slug: 'advisory-kind',
    term: 'Advisory kind',
    short: 'Whether an advisory is a real vulnerability or ecosystem metadata — unmaintained, unsound, notice, yanked or malware.',
    details: [
      'Most advisories are vulnerability reports: a CVE, GHSA or ecosystem entry describing exploitable code. RustSec additionally publishes non-vulnerability categories — unmaintained (the crate is abandoned), unsound (memory-unsafe or uncallable under some conditions), notice (informational) and yanked (the version was pulled from the registry). The OSV malicious-packages feed adds malware advisories (MAL-*).',
      'Aegis reads the category off the OSV record and badges non-vulnerability advisories so hygiene noise is distinguishable from real CVEs — a project with twenty unmaintained-crate notices does not have twenty vulnerabilities.',
    ],
    related: ['osv', 'cve-ghsa'],
  },
  {
    slug: 'activity-status',
    term: 'Activity status',
    short: 'PG Atlas classification of a project’s maintenance state: live, in-dev, discontinued or non-responsive.',
    details: [
      'PG Atlas assigns every public good an activity status. It affects how urgent a finding is and whether a disclosure channel is likely to reach anyone: a non-responsive or discontinued project carrying a critical vulnerability is a different kind of ecosystem risk than a live one.',
      'Aegis shows the status on project pages and uses it to contextualize findings rather than to filter them away — a dormant project with dependents still matters.',
    ],
    related: ['pony-factor', 'hygiene-profile'],
  },
  {
    slug: 'blast-radius',
    term: 'Blast radius',
    short: 'The set of downstream repos exposed to a vulnerable package — direct plus transitive dependents.',
    details: [
      'When a package gets a CVE, its blast radius is every public good that depends on it. Aegis traverses PG Atlas has-dependents edges up to a fixed depth and labels each exposure direct or transitive(depth).',
      'This ecosystem-wide view is the thing per-repo tools like Dependabot cannot produce — they see one repo’s graph, not the cross-project graph.',
    ],
    related: ['transitive-dependency', 'criticality', 'osv'],
  },
  {
    slug: 'criticality',
    term: 'Criticality',
    short: 'PG Atlas metric: the number of in-ecosystem repos that depend on a repo, directly or transitively.',
    details: [
      'Criticality is an integer count of dependents — not a 0–100 score. A vulnerability in a high-criticality repo propagates to everything built on top of it, so criticality is one of the largest weights in Aegis’s priority score.',
    ],
    related: ['blast-radius', 'priority-score', 'pony-factor'],
  },
  {
    slug: 'cve-ghsa',
    term: 'CVE · GHSA',
    short: 'CVE is the MITRE vulnerability identifier; GHSA is a GitHub Security Advisory ID. Both appear as aliases on one OSV record.',
    details: [
      'The same vulnerability is often tracked under several identifiers: a CVE assigned through MITRE, a GHSA on GitHub, and ecosystem-specific IDs like RUSTSEC or PYSEC.',
      'OSV records list these as aliases, and Aegis deduplicates on them so a vulnerability is never double-counted across sources.',
    ],
    related: ['osv', 'cvss', 'withdrawn-advisory'],
  },
  {
    slug: 'cvss',
    term: 'CVSS',
    short: 'Common Vulnerability Scoring System — a 0–10 severity score.',
    details: [
      'CVSS v3 expresses severity as a vector of metrics (attack vector, complexity, privileges required, impact) reduced to a 0–10 base score.',
      'Aegis computes the score from the OSV vector. When no vector exists it falls back to the advisory’s declared severity label — which is why some findings show unknown severity rather than a fabricated score.',
    ],
    related: ['kev', 'epss', 'priority-score'],
  },
  {
    slug: 'disclosure-channel',
    term: 'Disclosure channel',
    short: 'A ranked private route for reporting a vulnerability to a project.',
    details: [
      'Aegis answers “how do I report to this project” by ranking discovered channels: GitHub Private Vulnerability Reporting first, then contacts named in SECURITY.md (emails, bounty programs, forms), then security.txt on the project website, then a link to the policy itself.',
      'Public issues are never recommended — a public report is a public exploit.',
    ],
    related: ['pvr', 'security-md', 'security-txt', 'responsible-disclosure'],
  },
  {
    slug: 'epss',
    term: 'EPSS',
    short: 'Exploit Prediction Scoring System (FIRST) — the probability a CVE is exploited in the next 30 days.',
    details: [
      'EPSS uses a machine-learning model over CVE features and observed exploitation activity to score each CVE between 0 and 1.',
      'Aegis uses it as the exploitability signal for findings that are not in KEV, so rarely-exploited vulnerabilities rank below likely ones even at equal severity.',
    ],
    related: ['kev', 'cvss', 'priority-score'],
  },
  {
    slug: 'hygiene-profile',
    term: 'Hygiene profile',
    short: 'The set of per-project security-practice signals — policy present, PVR enabled, advisories published, Scorecard checks.',
    details: [
      'Rather than collapsing security posture into one number, Aegis reports each practice separately — “profiles, not a score” — so maintainers and the working group can see exactly which practice is missing.',
      'Signals include: has a SECURITY.md, PVR enabled, security.txt on the website, a dependency update tool configured, published advisories, and the oldest unpatched-but-fixable finding.',
    ],
    related: ['openssf-scorecard', 'disclosure-channel', 'priority-score'],
  },
  {
    slug: 'kev',
    term: 'KEV',
    short: 'CISA’s Known Exploited Vulnerabilities catalog — CVEs confirmed to be exploited in the wild.',
    details: [
      'Inclusion in CISA KEV means exploitation is not hypothetical: the vulnerability is being used in real attacks.',
      'Aegis gives KEV-listed findings the full exploitability weight in the priority score, ahead of any EPSS estimate.',
    ],
    related: ['epss', 'cvss', 'priority-score'],
  },
  {
    slug: 'manifest-probe',
    term: 'Lockfile probe',
    short: 'Manual review reads a repo’s committed lockfile at HEAD and matches it against OSV — recovering findings PG Atlas never ingested.',
    details: [
      'PG Atlas only sees dependency edges it crawled or received via SBOM; committed lockfiles it missed are invisible to the graph. A lockfile probe clones the repo, reads the pinned versions directly (Cargo.lock, package-lock.json, pnpm-lock.yaml, bun.lock, uv.lock, composer.lock, requirements.txt) and queries OSV for each.',
      'Findings recovered this way are emitted with confirmed confidence and a “verified present in lockfile at HEAD” note. The same review pass can annotate reachability manually — its verdicts are prefixed “manual:” with a one-line justification.',
    ],
    related: ['sbom', 'osv', 'verified-vs-inferred-edge', 'reachability'],
  },
  {
    slug: 'openssf-scorecard',
    term: 'OpenSSF Scorecard',
    short: 'Automated security-health checks for repos — branch protection, update tools, signed releases and more.',
    details: [
      'Scorecard runs a battery of checks against a repository and publishes results through a public API. Aegis surfaces the overall score and selected checks (dependency update tool, branch protection) as part of each project’s hygiene profile.',
    ],
    related: ['hygiene-profile'],
  },
  {
    slug: 'osv',
    term: 'OSV',
    short: 'Open Source Vulnerabilities — the distributed advisory database Aegis uses as its primary vulnerability source.',
    details: [
      'OSV.dev aggregates advisories from GHSA, PyPI, npm, Go, RustSec, Packagist, Pub, Maven, NuGet, RubyGems and more into a single schema with precise affected-version ranges.',
      'Aegis queries it in batches by PURL + version and deduplicates aliases so each underlying vulnerability produces a single finding.',
    ],
    related: ['cve-ghsa', 'purl', 'withdrawn-advisory'],
  },
  {
    slug: 'pony-factor',
    term: 'Pony factor',
    short: 'PG Atlas metric for maintainer concentration — the smallest set of contributors accounting for half a project’s commits.',
    details: [
      'A low pony factor means a project effectively depends on very few people: if they burn out or leave, security fixes stall. It is a bus-factor measure derived from commit history, and it feeds into ecosystem-weighted prioritization.',
    ],
    related: ['activity-status', 'criticality'],
  },
  {
    slug: 'priority-score',
    term: 'Priority score',
    short: 'The 0–100 ranking Aegis assigns each finding — severity, criticality, exploitability and exposure, adjusted for fixes and confidence.',
    details: [
      'Priority combines CVSS severity, PG Atlas criticality, KEV/EPSS exploitability, exposure depth and fix availability, minus a confidence penalty for range-only or inferred dependencies.',
      'The weights are versioned in the repo and every finding carries its own breakdown — see the Methodology page for the formula.',
    ],
    related: ['cvss', 'criticality', 'kev', 'epss'],
  },
  {
    slug: 'reachability',
    term: 'Reachability',
    short: 'Whether a repo’s code actually calls the vulnerable symbol — the strongest automated evidence that a finding is exploitable in practice.',
    details: [
      'For repos with Go findings, Aegis runs govulncheck call analysis at snapshot time: it shallow-clones the repo at HEAD, resolves its real module versions and checks call paths into the symbols each Go advisory names.',
      'Findings are labeled called (a call path into a vulnerable symbol exists), not-called (the module matches but the symbols are never invoked) or unflagged (govulncheck did not report the advisory at HEAD — the resolved module may differ from the PG Atlas edge, or already be patched). Repos that cannot be cloned or analyzed stay unlabeled — reachability is evidence, never fabricated.',
      'Reachability answers a narrower question than confidence: confidence says how sure we are the dependency exists, reachability says whether the vulnerable code is exercised. A verified-SBOM finding can still be unreachable; an inferred one can still be called.',
      'Verdicts can also come from manual review — inspecting cloned source and lockfiles — which applies the same called / not-called / unflagged labels to non-Go findings govulncheck cannot analyze. Manual verdicts carry a “manual:” justification in the trace.',
    ],
    related: ['verified-vs-inferred-edge', 'osv', 'blast-radius'],
  },
  {
    slug: 'purl',
    term: 'PURL',
    short: 'Package URL — a canonical package identifier (pkg:ecosystem/name@version).',
    details: [
      'A Package URL unambiguously identifies a package: its ecosystem (npm, cargo, PyPI, Go…), namespace, name and version.',
      'Aegis matches components to OSV advisories by PURL + version, which is what makes matching reliable across the many ecosystems Stellar public goods use.',
    ],
    related: ['osv', 'sbom'],
  },
  {
    slug: 'pvr',
    term: 'PVR',
    short: 'GitHub Private Vulnerability Reporting — confidential advisories filed on a repo. The preferred disclosure channel when enabled.',
    details: [
      'PVR gives researchers a private place to report issues directly to maintainers instead of opening a public issue. It is private by default, lands in the maintainer’s existing workflow, and produces a proper advisory record when published.',
      'Aegis ranks it as the top disclosure channel and tracks whether it is enabled as a hygiene signal.',
    ],
    related: ['disclosure-channel', 'security-md', 'responsible-disclosure'],
  },
  {
    slug: 'responsible-disclosure',
    term: 'Responsible disclosure',
    short: 'Reporting a vulnerability privately to the maintainer first, giving them time to fix before details become public.',
    details: [
      'Responsible (or coordinated) disclosure keeps a report private until a fix exists or an agreed window elapses — the opposite of opening a public issue, which hands attackers a working exploit.',
      'Aegis is built around this posture: it routes reporters to private channels, shows only already-public vulnerability data (OSV/GHSA/NVD), never stores embargoed reports or draft advisories, and only notifies maintainers who opt in. For critical findings on high-criticality projects, the spec allows an optional maintainer-first delay before prominent placement.',
    ],
    related: ['disclosure-channel', 'pvr'],
  },
  {
    slug: 'sbom',
    term: 'SBOM',
    short: 'Software Bill of Materials — the inventory of a repo’s dependencies.',
    details: [
      'A Software Bill of Materials enumerates the components a piece of software depends on. PG Atlas collects SPDX 2.3 SBOMs via a GitHub Action (pg-atlas-sbom-action) that reads the repository’s Dependency Graph and submits it with OIDC-verified repo identity.',
      'SBOMs are Aegis’s highest-value input: they carry resolved versions and PURLs, which map directly onto OSV queries. Repos without one fall back to inferred edges and produce lower-confidence findings.',
    ],
    related: ['verified-vs-inferred-edge', 'purl', 'osv'],
  },
  {
    slug: 'security-md',
    term: 'SECURITY.md',
    short: 'A repo file (root, .github/ or docs/) describing how to report vulnerabilities.',
    details: [
      'GitHub surfaces SECURITY.md on a repo’s Security tab. Aegis checks the standard locations — including the org-level .github repo as a fallback — and extracts emails, bounty-program URLs and reporting forms from the text as disclosure channels.',
    ],
    related: ['disclosure-channel', 'security-txt', 'pvr'],
  },
  {
    slug: 'security-txt',
    term: 'security.txt',
    short: 'RFC 9116 file served at /.well-known/security.txt on a website — security contacts for the deployed service.',
    details: [
      'Where SECURITY.md covers a repository, security.txt covers a domain. It is a strict machine-readable format with required Contact and Expires fields, and can be PGP-signed so researchers know it is authentic.',
      'Aegis fetches it for project websites that are not hosted on github.com, verifies a Contact field is present, and records it as a disclosure channel and hygiene signal.',
    ],
    related: ['security-md', 'disclosure-channel'],
  },
  {
    slug: 'transitive-dependency',
    term: 'Transitive dependency',
    short: 'A dependency of a dependency — exposure inherited indirectly through the package graph.',
    details: [
      'Most projects never declare a vulnerable package directly: it arrives inside something else they depend on. Aegis labels this exposure transitive(depth), where depth is the number of dependency hops between the repo and the affected package, and traverses it as part of blast-radius computation.',
    ],
    related: ['blast-radius', 'sbom'],
  },
  {
    slug: 'verified-vs-inferred-edge',
    term: 'Verified vs inferred edges',
    short: '“verified-sbom” dependencies come from a submitted SBOM; “inferred-shadow” edges are reconstructed by registry crawling.',
    details: [
      'Every dependency edge in PG Atlas carries a confidence label. verified-sbom edges come from a submitted SBOM tied to the repo’s identity; inferred-shadow edges are reconstructed by crawling package registries and may name a package the repo resembles rather than one it truly uses.',
      'Findings derived only from inferred edges are shown with inferred confidence and take a confidence penalty in the priority score.',
    ],
    related: ['sbom', 'priority-score'],
  },
  {
    slug: 'withdrawn-advisory',
    term: 'Withdrawn advisory',
    short: 'An advisory that was published, then retracted by its source as incorrect or a duplicate.',
    details: [
      'OSV records carry a withdrawn field. When an advisory is withdrawn, Aegis auto-closes the associated findings on the next re-match rather than leaving stale warnings attached to projects.',
    ],
    related: ['osv', 'cve-ghsa'],
  },
]
