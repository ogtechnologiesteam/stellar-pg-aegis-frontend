import { useState } from 'react'
import { Link } from 'react-router'
import { ArrowRight, Search } from 'lucide-react'
import { Card, EmptyState, PageHeader } from '../components/ui'
import { GLOSSARY } from '../lib/glossary'

export default function Glossary() {
  const [q, setQ] = useState('')
  const needle = q.trim().toLowerCase()
  const terms = GLOSSARY.filter((t) => !needle || t.term.toLowerCase().includes(needle) || t.short.toLowerCase().includes(needle))

  return (
    <>
      <PageHeader eyebrow="Reference" title="Glossary" description="Terms used across Aegis — vulnerability identifiers, PG Atlas metrics and disclosure concepts." />

      <Card className="mb-4 p-3">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter terms" className="input pl-9" aria-label="Filter glossary terms" />
        </div>
      </Card>

      {!terms.length ? (
        <Card>
          <EmptyState title="No terms match your filter" />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {terms.map((t) => (
            <Link key={t.slug} to={`/glossary/${t.slug}`} className="card group block p-5 transition hover:border-indigo-400/25 hover:bg-ink-850/80">
              <div className="flex items-center gap-2">
                <h3 className="text-[15px] font-medium text-slate-100">{t.term}</h3>
                <ArrowRight className="ml-auto size-4 shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-indigo-300" />
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-400">{t.short}</p>
            </Link>
          ))}
        </div>
      )}
    </>
  )
}
