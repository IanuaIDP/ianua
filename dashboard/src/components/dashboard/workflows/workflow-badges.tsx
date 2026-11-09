'use client';

import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { cn } from '@/utils/cn';

const toneStyles = {
  neutral: 'bg-white/15 text-white',
  ok: 'bg-primary/15 text-primary',
  warn: 'bg-orange/15 text-orange',
  bad: 'bg-error/15 text-error',
  info: 'bg-focus/15 text-focus',
} as const;

export type BadgeTone = keyof typeof toneStyles;

export function ToneBadge({ children, tone }: { children: ReactNode; tone: BadgeTone }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 shrink-0 items-center gap-1.25 rounded-md px-1.5 text-[10px] font-medium leading-none whitespace-nowrap',
        toneStyles[tone],
      )}
    >
      {children}
    </span>
  );
}

const workflowTones: Record<string, BadgeTone> = {
  archived: 'neutral',
  draft: 'neutral',
  published: 'ok',
};

/** Whether a workflow is on, in the words the dashboard uses for it. */
export function WorkflowStatusBadge({ status }: { status: string }) {
  const t = useTranslations('dashboard.workflows.status');
  const known = status === 'draft' || status === 'published' || status === 'archived';

  return (
    <ToneBadge tone={workflowTones[status] ?? 'neutral'}>{known ? t(status) : status}</ToneBadge>
  );
}

const runTones: Record<string, BadgeTone> = {
  cancelled: 'neutral',
  failed: 'bad',
  loop_ended: 'neutral',
  running: 'info',
  succeeded: 'ok',
  timed_out: 'warn',
};

/** How a run stands or ended. */
export function RunStatusBadge({ status }: { status: string }) {
  const t = useTranslations('dashboard.workflows.runStatus');
  const known = status in runTones;

  return (
    <ToneBadge tone={runTones[status] ?? 'neutral'}>
      {known ? t(status as keyof IntlRunStatus) : status}
    </ToneBadge>
  );
}

type IntlRunStatus = Record<
  'cancelled' | 'failed' | 'loop_ended' | 'running' | 'succeeded' | 'timed_out',
  string
>;

const phaseTones: Record<string, BadgeTone> = {
  abandoned: 'neutral',
  failed: 'bad',
  ready: 'info',
  running: 'info',
  skipped: 'neutral',
  stopped: 'neutral',
  succeeded: 'ok',
  waiting: 'neutral',
};

/** Where one step of a run stands. */
export function StepPhaseBadge({ phase }: { phase: string }) {
  const t = useTranslations('dashboard.workflows.phase');
  const known = phase in phaseTones;

  return (
    <ToneBadge tone={phaseTones[phase] ?? 'neutral'}>
      {known ? t(phase as keyof IntlPhase) : phase}
    </ToneBadge>
  );
}

type IntlPhase = Record<
  'abandoned' | 'failed' | 'ready' | 'running' | 'skipped' | 'stopped' | 'succeeded' | 'waiting',
  string
>;

const exposureTones: Record<string, BadgeTone> = {
  confidential: 'warn',
  internal: 'info',
  public: 'neutral',
  restricted: 'bad',
};

/** How sensitive the data of a run or step is. */
export function ExposureBadge({ exposure }: { exposure: string }) {
  const t = useTranslations('dashboard.workflows.exposure');
  const known = exposure in exposureTones;

  return (
    <ToneBadge tone={exposureTones[exposure] ?? 'neutral'}>
      {known ? t(exposure as keyof IntlExposure) : exposure}
    </ToneBadge>
  );
}

type IntlExposure = Record<'confidential' | 'internal' | 'public' | 'restricted', string>;
