import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router'
import { BookA, BookOpen, Boxes, LayoutDashboard, Menu, Moon, Search, ShieldAlert, Siren, Sun, X } from 'lucide-react'
import { api, useSummary } from '../api'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/projects', label: 'Projects', icon: Boxes },
  { to: '/advisories', label: 'Advisories', icon: ShieldAlert },
  { to: '/disclose', label: 'Report a vulnerability', icon: Siren },
  { to: '/methodology', label: 'Methodology', icon: BookOpen },
  { to: '/glossary', label: 'Glossary', icon: BookA },
]

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <img src="/favicon.svg" alt="" className="size-8 drop-shadow-[0_0_12px_rgba(99,102,241,0.45)]" />
      <div className="leading-tight">
        <div className="text-[15px] font-semibold tracking-tight text-white">PG Aegis</div>
        <div className="text-[11px] text-slate-500">Stellar public goods security</div>
      </div>
    </div>
  )
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { data: summary } = useSummary()
  const generated = summary?.generated_at
    ? new Date(summary.generated_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
    : null
  return (
    <nav className="flex h-full flex-col gap-6 p-4">
      <div className="px-2 pt-1">
        <Logo />
      </div>
      <ul className="flex flex-col gap-0.5">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              onClick={onNavigate}
              className={({ isActive }) =>
                clsx(
                  'group flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition',
                  isActive ? 'bg-gradient-to-r from-indigo-500/20 to-cyan-500/5 text-white ring-1 ring-indigo-400/20 ring-inset' : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-100',
                )
              }
            >
              <Icon className="size-4 opacity-80" />
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="mt-auto space-y-3">
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-xs text-slate-400">
          <div className="mb-1 font-medium text-slate-300">Data sources</div>
          PG Atlas · OSV.dev · GitHub · OpenSSF Scorecard · CISA KEV · EPSS
        </div>
        {api.mode === 'snapshot' && (
          <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/[0.05] p-3 text-xs text-cyan-100/80">
            <div className="mb-0.5 font-semibold">Snapshot data{generated ? ` · ${generated}` : ''}</div>
            Real data from public sources, refreshed periodically. GitHub disclosure checks don't cover every repo yet — “Unknown” means not yet checked, not absent.
          </div>
        )}
      </div>
    </nav>
  )
}

function GlobalSearch() {
  const navigate = useNavigate()
  const ref = useRef<HTMLInputElement>(null)
  const [value, setValue] = useState('')

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        ref.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <form
      className="relative w-full max-w-md"
      onSubmit={(e) => {
        e.preventDefault()
        const q = value.trim()
        navigate(/^(GHSA|CVE|RUSTSEC|PYSEC|GO|MAL|GH|OSV)[-\d]/i.test(q) ? `/advisories?search=${encodeURIComponent(q)}` : `/projects?search=${encodeURIComponent(q)}`)
      }}
    >
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500" />
      <input ref={ref} value={value} onChange={(e) => setValue(e.target.value)} placeholder="Search projects, packages or advisory IDs" className="input pr-14 pl-9" aria-label="Global search" />
      <kbd className="pointer-events-none absolute top-1/2 right-2.5 hidden -translate-y-1/2 rounded-md border border-white/10 bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-slate-500 sm:block">⌘K</kbd>
    </form>
  )
}

function ThemeToggle() {
  const [light, setLight] = useState(() => document.documentElement.classList.contains('light'))
  return (
    <button
      className="grid size-9 cursor-pointer place-items-center rounded-lg text-slate-400 transition hover:bg-white/5 hover:text-slate-200"
      onClick={() => {
        const next = !light
        setLight(next)
        document.documentElement.className = next ? 'light' : 'dark'
        localStorage.setItem('aegis-theme', next ? 'light' : 'dark')
      }}
      aria-label={light ? 'Switch to dark mode' : 'Switch to light mode'}
      title={light ? 'Switch to dark mode' : 'Switch to light mode'}
    >
      {light ? <Moon className="size-4" /> : <Sun className="size-4" />}
    </button>
  )
}

export function Layout() {
  const [open, setOpen] = useState(false)
  const { pathname } = useLocation()

  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [pathname])

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-white/[0.05] bg-ink-950/60 backdrop-blur-xl lg:block">
        <Sidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 border-r border-white/[0.06] bg-ink-900">
            <button className="absolute top-4 right-3 grid size-8 cursor-pointer place-items-center rounded-lg text-slate-400 hover:bg-white/5" onClick={() => setOpen(false)} aria-label="Close menu">
              <X className="size-4" />
            </button>
            <Sidebar onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-white/[0.05] bg-ink-950/70 px-4 backdrop-blur-xl md:px-8">
          <button className="grid size-9 cursor-pointer place-items-center rounded-lg text-slate-300 hover:bg-white/5 lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu className="size-5" />
          </button>
          <GlobalSearch />
          <div className="ml-auto flex items-center gap-2">
            <ThemeToggle />
            {api.mode === 'snapshot' ? (
              <span className="hidden items-center gap-1.5 rounded-full border border-cyan-400/25 bg-cyan-400/10 px-2.5 py-1 text-[11px] font-medium text-cyan-100 sm:inline-flex">
                <span className="size-1.5 rounded-full bg-cyan-300" /> Snapshot
              </span>
            ) : (
              <span className="hidden items-center gap-1.5 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2.5 py-1 text-[11px] font-medium text-emerald-200 sm:inline-flex">
                <span className="size-1.5 rounded-full bg-emerald-300" /> Live API
              </span>
            )}
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 md:px-8">
          <Outlet />
        </main>
        <footer className="border-t border-white/[0.04] px-8 py-5 text-xs text-slate-600">
          Stellar PG Aegis surfaces only publicly disclosed vulnerability data. Never report vulnerabilities in public issues.
        </footer>
      </div>
    </div>
  )
}
