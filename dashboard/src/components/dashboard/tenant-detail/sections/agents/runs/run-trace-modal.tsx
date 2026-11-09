'use client';

import { useTranslations } from 'next-intl';
import { useQuery } from '@tanstack/react-query';

import { Modal } from '@/components/ui/modal';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { getAgentRun, getApiErrorMessage } from '@/lib/api';
import type { RunSummary, RunStepOutcome } from '@/types/run';
import { cn } from '@/utils/cn';
import { getRunDisplayId } from '@/utils/run';

type RunTraceModalProps = {
  onClose: () => void;
  run: RunSummary | null;
};

const outcomeStyles: Record<RunStepOutcome, string> = {
  allowed: 'text-primary',
  answered: 'text-white',
  denied: 'text-error',
};

function formatMicros(micros: number) {
  return (micros / 1_000_000).toFixed(2);
}

export function RunTraceModal({ onClose, run }: RunTraceModalProps) {
  const t = useTranslations('dashboard.agents.runs.trace');
  const { orgSlug, tenantSlug, agentId } = useAgentRouteParams();
  const {
    data: detail,
    error,
    isLoading,
    isFetching,
    refetch,
  } = useQuery({
    enabled: Boolean(run && orgSlug && tenantSlug && agentId),
    staleTime: 0,
    queryKey: ['agent-run', orgSlug, tenantSlug, agentId, run?.id],
    queryFn: () => getAgentRun(orgSlug ?? '', tenantSlug, agentId, run?.id ?? ''),
  });

  return (
    <Modal
      open={Boolean(run)}
      onClose={onClose}
      title={run ? t('title', { id: getRunDisplayId(run) }) : undefined}
      description={run?.goal}
    >
      {isLoading ? (
        <p role="status" className="text-xs text-textGray">
          {t('loading')}
        </p>
      ) : null}
      {error ? (
        <div role="alert" className="flex flex-col gap-3">
          <p className="text-xs text-error">{getApiErrorMessage(error, t('loadFailed'))}</p>
          <button
            type="button"
            disabled={isFetching}
            onClick={() => void refetch()}
            className="self-start rounded-md border border-borderGray px-3 py-2 text-xs text-white transition hover:bg-hoverBg disabled:opacity-40"
          >
            {t('retry')}
          </button>
        </div>
      ) : null}
      {run && detail && !error ? (
        <div className="flex flex-col gap-3">
          <p className="text-[10px] font-medium text-textGray">
            {t('startedBy', { name: detail.startedBy ?? t('someone'), date: detail.created })}
            {' · '}
            {t('usage', {
              input: detail.usage.inputTokens,
              output: detail.usage.outputTokens,
            })}
            {detail.spentMicros > 0 || detail.spendLimitMicros !== null
              ? ` · ${t('spent', {
                  limit: formatMicros(detail.spendLimitMicros ?? 0),
                  spent: formatMicros(detail.spentMicros),
                })}`
              : ''}
          </p>
          {detail.answer ? (
            <p className="wrap-break-word rounded-lg border border-borderGray p-3 text-xs text-white">
              {detail.answer}
            </p>
          ) : null}
          {detail.steps.length === 0 ? (
            <p className="text-xs text-textGray">{t('empty')}</p>
          ) : (
            detail.steps
              .slice()
              .sort((a, b) => a.seq - b.seq)
              .map((step) => (
                <div key={step.seq} className="rounded-lg border border-borderGray p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-white">
                      {t('step', { number: step.seq })}
                      {step.tool ? <span className="text-textGray"> · {step.tool}</span> : null}
                    </span>
                    <span className={cn('text-[10px] font-semibold', outcomeStyles[step.outcome])}>
                      {t(`outcomes.${step.outcome}`)}
                    </span>
                  </div>
                  {step.arguments ? (
                    <p className="mt-1.5 wrap-break-word font-mono text-[10px] text-textGray">
                      {step.arguments}
                    </p>
                  ) : null}
                  <p className="mt-1.5 text-xs text-white">{step.detail}</p>
                </div>
              ))
          )}
        </div>
      ) : null}
    </Modal>
  );
}
