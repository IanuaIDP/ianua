'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { TRIGGER_KEY } from '@/components/dashboard/workflows/builder/constants';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { WorkflowNeedsAccount } from '@/types/workflows';

type HeldBannerProps = {
  canStartDraft: boolean;
  isStartingDraft: boolean;
  needsAccount: WorkflowNeedsAccount;
  onStartDraft: () => void;
};

/** Says why a version in service starts nothing, until a next version is published. */
export function HeldBanner({
  canStartDraft,
  isStartingDraft,
  needsAccount,
  onStartDraft,
}: HeldBannerProps) {
  const t = useTranslations('dashboard.workflowBuilder.held');
  const tReason = useLooseTranslations('dashboard.workflowBuilder.held.reasons');
  const { tenantPathFor } = useBuilderContext();
  const nodes = useWorkingCopy((state) => state.copy.nodes);
  const place =
    needsAccount.at === TRIGGER_KEY
      ? t('atTrigger')
      : t('atStep', {
          step: nodes.find((node) => node.key === needsAccount.at)?.name ?? needsAccount.at,
        });

  return (
    <div className="flex items-start gap-3 rounded-lg bg-orange/10 p-3 text-xs text-white">
      <span className="material-symbols-rounded text-orange" aria-hidden="true">
        pause_circle
      </span>
      <div className="min-w-0 flex-1">
        <p className="font-semibold">{t('title')}</p>
        <p className="mt-0.5 text-textGray">
          {t('why', {
            place,
            reason: tReason.has(needsAccount.reason)
              ? tReason(needsAccount.reason)
              : needsAccount.reason,
          })}
        </p>
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        <Link
          className="inline-flex items-center rounded-lg bg-surfaceChip px-3 py-1.5 font-semibold text-white hover:bg-borderGray"
          href={tenantPathFor('connected-accounts')}
        >
          {t('openAccounts')}
        </Link>
        {canStartDraft ? (
          <SmallButton disabled={isStartingDraft} onClick={onStartDraft}>
            {t('startDraft')}
          </SmallButton>
        ) : null}
      </div>
    </div>
  );
}
