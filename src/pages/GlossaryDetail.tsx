import { Link, useParams } from 'react-router'
import { ArrowLeft, ArrowRight } from 'lucide-react'
import { Card, CardHeader, EmptyState, PageHeader } from '../components/ui'
import { GLOSSARY, type GlossaryTerm } from '../lib/glossary'

export default function GlossaryDetail() {
  const { slug = '' } = useParams()
  const term = GLOSSARY.find((t) => t.slug === slug)

  if (!term)
    return (
      <>
        <Link to="/glossary" className="mb-4 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
          <ArrowLeft className="size-3.5" /> Glossary
        </Link>
        <Card>
          <EmptyState title="Term not found" description={`No glossary entry for “${slug}”.`} />
        </Card>
      </>
    )

  const related = term.related.map((s) => GLOSSARY.find((t) => t.slug === s)).filter((t): t is GlossaryTerm => t != null)

  return (
    <>
      <Link to="/glossary" className="mb-4 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
        <ArrowLeft className="size-3.5" /> Glossary
      </Link>
      <PageHeader eyebrow="Glossary" title={term.term} description={term.short} />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="space-y-4 p-5">
            {term.details.map((p, i) => (
              <p key={i} className="text-sm leading-relaxed text-slate-300">
                {p}
              </p>
            ))}
          </div>
        </Card>

        {related.length > 0 && (
          <Card>
            <CardHeader title="Related terms" />
            <ul className="divide-y divide-white/[0.04]">
              {related.map((r) => (
                <li key={r.slug}>
                  <Link to={`/glossary/${r.slug}`} className="group flex items-center gap-2 px-5 py-3 text-sm text-slate-200 transition hover:bg-white/[0.03] hover:text-white">
                    {r.term}
                    <ArrowRight className="ml-auto size-3.5 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-indigo-300" />
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </>
  )
}
