'use client';

import { useTranslations } from 'next-intl';

import { Tooltip } from '@/components/ui/tooltip';
import type { DelegationBudget } from '@/types/delegation';
import { formatDurationShort } from '@/utils/date';

type DelegationBudgetBadgeProps = {
  budget: DelegationBudget;
};

export function DelegationBudgetBadge({ budget }: DelegationBudgetBadgeProps) {
  const t = useTranslations('dashboard.delegations.budget');
  const hasUsage = budget.usedRequests != null;
  const usagePercent = hasUsage
    ? Math.min(100, Math.round((budget.usedRequests! / budget.maxRequests) * 100))
    : 0;
  const tooltipContent = hasUsage
    ? t('used', {
        max: budget.maxRequests,
        used: budget.usedRequests ?? 0,
        window: formatDurationShort(budget.windowSeconds),
      })
    : t('untracked', {
        max: budget.maxRequests,
        window: formatDurationShort(budget.windowSeconds),
      });

  return (
    <Tooltip content={tooltipContent} side="top">
      <span className="flex items-center gap-1.5">
        <span className="inline-flex h-5 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
          {hasUsage ? budget.usedRequests : '—'}/{budget.maxRequests}
        </span>
        <span className="h-1.5 w-30 overflow-hidden rounded-full bg-white/15" aria-hidden>
          <span
            className="block h-full rounded-full bg-primary"
            style={{ width: `${usagePercent}%` }}
          />
        </span>
      </span>
    </Tooltip>
  );
}
