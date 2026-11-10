import clsx from 'clsx'
import { AtSign, ExternalLink, FileText, Github, Globe, HelpCircle, ShieldCheck, Trophy } from 'lucide-react'
import type { ChannelKind, DisclosureChannel } from '../api/types'
import { CHANNEL_LABEL, relativeTime } from '../lib/format'
import { CopyButton, Pill } from './ui'

const ICON: Record<ChannelKind, typeof Github> = { pvr: Github, email: AtSign, url: Globe, bounty: Trophy, security_txt: FileText, policy: FileText, other: HelpCircle }

const isUrl = (v: string) => /^https?:\/\//.test(v)

export function DisclosureChannels({ channels, compact = false }: { channels: DisclosureChannel[]; compact?: boolean }) {
  if (!channels.length) {
    return <p className="text-sm text-slate-500">No disclosure channel could be found for this project.</p>
  }
  const hasPolicy = channels.some((c) => c.kind !== 'other')
  const onlyFallback = channels.length > 0 && channels.every((c) => c.kind === 'other')
  return (
    <div className="space-y-2.5">
      {onlyFallback && (
        <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.06] px-3 py-2.5 text-xs text-amber-200/90">
          No published security policy was found for this project's repos (or they have not been enriched yet). Contact the maintainer privately — do not include vulnerability details in public issues.
        </div>
      )}
      {!hasPolicy && !onlyFallback && (
        <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.06] px-3 py-2.5 text-xs text-amber-200/90">
          This project has no published security policy. Contact the maintainer privately and ask for a secure channel — do not include vulnerability details in public issues.
        </div>
      )}
      {channels.map((c, i) => {
        const Icon = ICON[c.kind]
        const primary = i === 0 && c.kind !== 'other'
        return (
          <div key={`${c.kind}-${c.value}`} className={clsx('flex items-center gap-3 rounded-xl border p-3', primary ? 'border-indigo-400/30 bg-indigo-500/[0.07]' : 'border-white/[0.06] bg-white/[0.02]')}>
            <div className={clsx('grid size-9 shrink-0 place-items-center rounded-lg', primary ? 'bg-indigo-500/20 text-indigo-200' : 'bg-white/[0.04] text-slate-400')}>
              <Icon className="size-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-slate-100">{CHANNEL_LABEL[c.kind]}</span>
                {primary && (
                  <Pill tone="indigo">
                    <ShieldCheck className="size-3" /> Recommended
                  </Pill>
                )}
                {c.repo && <Pill title="Repository this channel was found on">{c.repo}</Pill>}
              </div>
              <div className="truncate font-mono text-xs text-slate-400" title={c.value}>
                {c.value}
              </div>
              {!compact && (
                <div className="mt-1 text-[11px] text-slate-600">
                  Verified {relativeTime(c.last_verified_at)} · extracted by {c.extracted_by}
                  {c.source_url && (
                    <>
                      {' · '}
                      <a href={c.source_url} target="_blank" rel="noreferrer" className="text-slate-500 hover:text-slate-300">
                        source
                      </a>
                    </>
                  )}
                </div>
              )}
            </div>
            <CopyButton value={c.value} />
            {isUrl(c.value) && (
              <a href={c.value} target="_blank" rel="noreferrer" className="grid size-8 shrink-0 place-items-center rounded-lg text-slate-400 hover:bg-white/[0.06] hover:text-white" aria-label="Open">
                <ExternalLink className="size-4" />
              </a>
            )}
          </div>
        )
      })}
    </div>
  )
}
