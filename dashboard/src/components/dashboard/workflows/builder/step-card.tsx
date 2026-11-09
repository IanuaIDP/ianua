'use client';

import type { KeyboardEvent, ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import {
  CARD_HEIGHT,
  CARD_WIDTH,
  PORT_OFFSET_Y,
} from '@/components/dashboard/workflows/builder/constants';
import type { WorkflowPort } from '@/types/workflow-graph';
import type { StepState } from '@/types/workflows';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { cn } from '@/utils/cn';

const PHASE_TONES: Record<string, { className: string; icon: string }> = {
  abandoned: { className: 'bg-surfaceChip text-textGray', icon: 'block' },
  failed: { className: 'bg-error/15 text-error', icon: 'error' },
  ready: { className: 'bg-orange/15 text-orange', icon: 'hourglass_top' },
  running: { className: 'bg-orange/15 text-orange', icon: 'progress_activity' },
  skipped: { className: 'bg-surfaceChip text-textGray', icon: 'block' },
  stopped: { className: 'bg-error/15 text-error', icon: 'block' },
  succeeded: { className: 'bg-green/15 text-green', icon: 'check_circle' },
  waiting: { className: 'bg-surfaceChip text-textGray', icon: 'hourglass_top' },
};

export type StepFlag = 'leak' | 'problem' | null;

type StepCardProps = {
  addablePorts: WorkflowPort[];
  cardKey: string;
  flag: StepFlag;
  hasInPort: boolean;
  isDimmed: boolean;
  isSelected: boolean;
  line: string;
  mark: ReactNode;
  number: number | null;
  onAddAfter?: (port: WorkflowPort) => void;
  onSelect: () => void;
  outPorts: WorkflowPort[];
  showPorts: boolean;
  state: StepState | null;
  title: string;
  x: number;
  y: number;
};

export function StepCard({
  addablePorts,
  cardKey,
  flag,
  hasInPort,
  isDimmed,
  isSelected,
  line,
  mark,
  number,
  onAddAfter,
  onSelect,
  outPorts,
  showPorts,
  state,
  title,
  x,
  y,
}: StepCardProps) {
  const t = useTranslations('dashboard.workflowBuilder.canvas');
  const tPhase = useLooseTranslations('dashboard.workflowBuilder.phases');
  const phase = state ? (PHASE_TONES[state.phase] ?? PHASE_TONES.waiting) : null;

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelect();
    }
  }

  return (
    <div
      role="button"
      tabIndex={0}
      aria-pressed={isSelected}
      data-card-key={cardKey}
      onKeyDown={handleKeyDown}
      className={cn(
        'group absolute flex items-center gap-3 rounded-lg border bg-surfaceRaised px-3.5 shadow-dropdown transition-[border-color,opacity] outline-none select-none focus-visible:border-focus',
        isSelected
          ? 'border-primary shadow-primary-soft'
          : 'border-transparent hover:border-borderGray',
        isDimmed && 'opacity-40',
      )}
      style={{ height: CARD_HEIGHT, left: x, top: y, width: CARD_WIDTH }}
    >
      {number !== null ? (
        <span
          className={cn(
            'absolute -left-2.5 -top-2.5 flex size-5.5 items-center justify-center rounded-full text-[11px] font-semibold',
            isSelected ? 'bg-primary text-black' : 'bg-menuHover text-white',
          )}
        >
          {number}
        </span>
      ) : null}

      {hasInPort ? (
        <span
          data-in-port
          className="absolute left-0 size-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-textGray bg-surfaceRaised"
          style={{ top: PORT_OFFSET_Y.next }}
        />
      ) : null}

      <span className="relative shrink-0">
        {mark}
        {flag ? (
          <i
            title={flag === 'leak' ? t('leakFlag') : t('problemFlag')}
            className={cn(
              'absolute -right-1 -top-1 size-2.75 rounded-full shadow-[0_0_0_3px_#1E1E1B]',
              flag === 'leak' ? 'bg-error' : 'bg-orange',
            )}
          />
        ) : null}
      </span>

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold text-white">{title}</p>
        <p className="truncate text-xs text-textGray">{line}</p>
      </div>

      {phase && state ? (
        <span
          className={cn(
            'absolute -bottom-2.5 left-3.5 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium',
            phase.className,
          )}
        >
          <span
            className={cn(
              'material-symbols-rounded text-sm!',
              state.phase === 'running' && 'animate-spin',
            )}
            aria-hidden="true"
          >
            {phase.icon}
          </span>
          {tPhase.has(state.phase) ? tPhase(state.phase) : state.phase}
        </span>
      ) : null}

      {outPorts.map((port) => (
        <span
          key={port}
          data-out-port={showPorts ? port : undefined}
          className={cn(
            'absolute left-full size-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-surfaceRaised bg-textGray',
            showPorts && 'cursor-crosshair hover:size-4 hover:bg-primary',
            isSelected && 'bg-primary',
          )}
          style={{ top: PORT_OFFSET_Y[port] }}
        />
      ))}

      {onAddAfter
        ? addablePorts.map((port) => (
            <button
              key={port}
              type="button"
              data-add-button
              aria-label={t('addAfter')}
              title={t('addAfter')}
              onClick={() => onAddAfter(port)}
              className={cn(
                'absolute -right-8 size-6 -translate-y-1/2 items-center justify-center rounded-full bg-primary text-black',
                isSelected ? 'flex' : 'hidden group-hover:flex group-focus-within:flex',
              )}
              style={{ top: PORT_OFFSET_Y[port] }}
            >
              <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                add
              </span>
            </button>
          ))
        : null}
    </div>
  );
}
