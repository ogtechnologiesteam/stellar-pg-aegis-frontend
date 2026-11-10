import { Link } from 'react-router'
import { Card, CardHeader, ConfidencePill, PageHeader } from '../components/ui'
import { PRIORITY_WEIGHTS } from '../lib/priority'

const FACTORS: { key: keyof typeof PRIORITY_WEIGHTS; label: string; desc: string }[] = [
  { key: 'severity', label: 'Severity', desc: 'CVSS v3 base score computed from the OSV vector, or the advisory’s severity label when no score exists.' },
  { key: 'criticality', label: 'Criticality', desc: 'PG Atlas criticality of the affected repo — its count of transitive in-ecosystem dependents, log-normalized.' },
  { key: 'exploitability', label: 'Exploitability', desc: 'Full weight if the CVE is in CISA’s Known Exploited Vulnerabilities catalog, otherwise the FIRST EPSS probability.' },
  { key: 'exposure', label: 'Exposure', desc: 'How many repos in the ecosystem depend on the affected repo (PG Atlas dependents), log-normalized.' },
  { key: 'fix_available', label: 'Fix available', desc: 'Boosts findings that can be fixed right now by upgrading to a patched version.' },
  { key: 'confidence_penalty', label: 'Confidence penalty', desc: 'Subtracted when only a version range is known, or the dependency was inferred rather than declared in an SBOM.' },
]

const SOURCES = [
  ['PG Atlas', 'Public-good projects, repos, dependency edges (verified SBOMs + inferred), dependents, criticality, adoption and pony factor.'],
  ['OSV.dev', 'Vulnerability matching by PURL + version. Aggregates GHSA, PyPI, npm, Go, RustSec, Packagist, Pub, Maven, NuGet, RubyGems and more.'],
  ['GitHub', 'SECURITY.md, private vulnerability reporting status, repository-published advisories, Dependabot / Renovate config.'],
  ['security.txt', 'RFC 9116 file fetched at /.well-known/security.txt on each project website (non-GitHub). Presence is verified by a Contact: field; adds a ranked disclosure channel and a hygiene check.'],
  ['OpenSSF Scorecard', 'Overall repo score where Scorecard has scanned the repository.'],
  ['CISA KEV · FIRST EPSS', 'Exploitation signals used for prioritization.'],
]

const DISCLOSURE_RANKING = [
  'GitHub Private Vulnerability Reporting, when enabled on any project repo',
  'Contacts named in SECURITY.md — security emails, bounty program URLs (HackerOne, Immunefi, …), reporting forms',
  'security.txt on the project’s website',
  'A link to the SECURITY.md policy itself when no concrete contact could be extracted',
  'Fallback: the project’s repo URL, flagged as a last resort',
]

const CONFIDENCE = [
  ['confirmed', 'Exact package version from a verified SBOM submitted to PG Atlas.'],
  ['possible', 'Only a version range is declared; shown for the lowest matching version (worst case).'],
  ['inferred', 'Dependency edge came from PG Atlas registry crawling, not a submitted SBOM.'],
] as const

export default function Methodology() {
  return (
    <>
      <PageHeader eyebrow="Transparency" title="Methodology" description="How Aegis matches vulnerabilities, ranks findings and routes disclosures. Weights are versioned and published with the backend." />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Priority score (0–100)" subtitle="Specification FR5" />
          <div className="space-y-4 p-5">
            <pre className="overflow-x-auto rounded-xl border border-white/[0.06] bg-ink-950/60 p-4 font-mono text-xs leading-relaxed text-cyan-200">
              {`priority = ${PRIORITY_WEIGHTS.severity}·severity + ${PRIORITY_WEIGHTS.criticality}·criticality
         + ${PRIORITY_WEIGHTS.exploitability}·exploitability + ${PRIORITY_WEIGHTS.exposure}·exposure
         + ${PRIORITY_WEIGHTS.fix_available}·fix_available − ${PRIORITY_WEIGHTS.confidence_penalty}·confidence_penalty`}
            </pre>
            <ul className="space-y-3">
              {FACTORS.map((f) => (
                <li key={f.key} className="flex gap-3">
                  <span className="mt-0.5 w-10 shrink-0 text-right font-mono text-xs text-indigo-300">{PRIORITY_WEIGHTS[f.key]}</span>
                  <div>
                    <div className="text-sm font-medium text-slate-200">{f.label}</div>
                    <p className="text-xs text-slate-400">{f.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Finding confidence" />
            <ul className="space-y-3 p-5 text-sm text-slate-300">
              {CONFIDENCE.map(([c, d]) => (
                <li key={c} className="flex items-start gap-3">
                  <ConfidencePill confidence={c} /> {d}
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <CardHeader title="Data sources" />
            <dl className="divide-y divide-white/[0.04]">
              {SOURCES.map(([name, desc]) => (
                <div key={name} className="grid grid-cols-3 gap-3 px-5 py-3 text-sm">
                  <dt className="font-medium text-slate-200">{name}</dt>
                  <dd className="col-span-2 text-xs text-slate-400">{desc}</dd>
                </div>
              ))}
            </dl>
          </Card>

          <Card>
            <CardHeader title="Disclosure routing" subtitle="Channels ranked by preference — spec FR6" />
            <ol className="list-decimal space-y-2 p-5 pl-9 text-xs text-slate-400">
              {DISCLOSURE_RANKING.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ol>
          </Card>

          <Card className="p-5 text-xs leading-relaxed text-slate-400">
            <div className="mb-1 text-sm font-medium text-slate-200">Responsible disclosure posture</div>
            Aegis only shows vulnerability data that is already public. It never stores embargoed reports or draft advisories, and it only notifies maintainers who opt in. It reports each security practice separately, as a profile, rather than combining them into a single score. Values marked “unknown” were not collected — nothing here is estimated.
          </Card>
        </div>
      </div>

      <div className="mt-4 text-xs text-slate-500">
        Unfamiliar with a term? See the{' '}
        <Link to="/glossary" className="text-indigo-300 hover:text-indigo-200">
          glossary →
        </Link>
      </div>
    </>
  )
}
