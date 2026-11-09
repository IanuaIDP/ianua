'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';

import { JsonView } from '@/components/dashboard/workflows/json-view';
import { ExposureBadge, StepPhaseBadge } from '@/components/dashboard/workflows/workflow-badges';
import { WithheldNotice } from '@/components/dashboard/workflows/withheld-notice';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { StepState } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { cn } from '@/utils/cn';

function StepLoopPasses({ step }: { step: StepState }) {
  const t = useTranslations('dashboard.workflows.run');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();

  if (!step.passes) {
    return null;
  }

  const { approval, done, executions, items } = step.passes;

  return (
    <div className="flex flex-col gap-1.5 text-xs text-textGray">
      <p>{t('passes', { done, items })}</p>
      {approval === 'waiting' ? <p className="text-orange">{t('passesWaiting')}</p> : null}
      <ul className="flex flex-wrap gap-2">
        {executions.map((executionId, index) => (
          <li key={executionId}>
            <Link
              className="text-primary hover:underline"
              href={getTenantScopedPath(
                isTenantView,
                orgSlug,
                tenantSlug,
                `workflows/runs/${executionId}`,
                `workflows/runs/${executionId}`,
              )}
            >
              {t('passNumber', { number: index + 1 })}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function RunStepDetail({ step }: { step: StepState }) {
  const t = useTranslations('dashboard.workflows.run');
  const tFailure = useLooseTranslations('dashboard.workflows.failureCodes');

  if (step.withheld) {
    return <WithheldNotice />;
  }

  return (
    <div className="flex flex-col gap-3">
      {step.failure ? (
        <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error">
          {tFailure.has(step.failure.code) ? tFailure(step.failure.code) : step.failure.code}
          {step.failure.detail ? `: ${step.failure.detail}` : ''}
        </p>
      ) : null}
      <StepLoopPasses step={step} />
      {step.input !== undefined && step.input !== null ? (
        <div>
          <p className="mb-1 text-xs font-medium text-textGray">{t('input')}</p>
          <JsonView value={step.input} />
        </div>
      ) : null}
      {step.output !== undefined && step.output !== null ? (
        <div>
          <p className="mb-1 text-xs font-medium text-textGray">{t('output')}</p>
          <JsonView value={step.output} />
        </div>
      ) : null}
      {step.port ? (
        <p className="text-xs text-textGray">
          {t('wayOut')} <span className="text-white">{step.port}</span>
        </p>
      ) : null}
    </div>
  );
}

/** The steps of a run in order; opening one shows what went in and came out. */
export function RunStepList({ steps }: { steps: StepState[] }) {
  const [openKey, setOpenKey] = useState<string | null>(null);

  return (
    <ol className="divide-y divide-borderGray rounded-lg border border-borderGray bg-cardBg">
      {steps.map((step) => {
        const isOpen = openKey === step.key;

        return (
          <li key={step.key}>
            <button
              type="button"
              aria-expanded={isOpen}
              onClick={() => setOpenKey(isOpen ? null : step.key)}
              className={cn(
                'flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-hoverBg',
              )}
            >
              <span className="min-w-0 flex-1 truncate text-sm font-medium text-white">
                {step.name}
              </span>
              {step.exposure ? <ExposureBadge exposure={step.exposure} /> : null}
              <StepPhaseBadge phase={step.phase} />
              <span className="material-symbols-rounded text-base! text-textGray" aria-hidden>
                {isOpen ? 'expand_less' : 'expand_more'}
              </span>
            </button>
            {isOpen ? (
              <div className="border-t border-borderGray px-4 py-3">
                <RunStepDetail step={step} />
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}
