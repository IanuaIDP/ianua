'use client';

import { useLocale, useTranslations } from 'next-intl';

import { Tooltip } from '@/components/ui/tooltip';
import type { ModelProviderTestState } from '@/types/model-provider';
import { formatDateTime, formatRelativeTime } from '@/utils/date';
import { getFailureMessage } from '@/utils/model-provider';

type TestStatusProps = {
  testState: ModelProviderTestState | undefined;
};

export function TestStatus({ testState }: TestStatusProps) {
  const t = useTranslations('dashboard.modelProviders.testStatus');
  const locale = useLocale();

  if (!testState || testState.status === 'pending') {
    return testState?.status === 'pending' ? (
      <span className="text-textGray">{t('testing')}</span>
    ) : (
      <span className="text-white">{t('notTested')}</span>
    );
  }

  const isPassed = testState.status === 'success' && testState.result.ok;
  const failureMessage = getFailureMessage(testState);

  if (isPassed) {
    return (
      <span className="flex items-center gap-1">
        <span className="font-medium text-primary">{t('passed')}</span>
        <span className="text-primary">· {formatDateTime(testState.testedAt)}</span>
      </span>
    );
  }

  return (
    <Tooltip content={failureMessage ?? t('connectionFailed')} side="top">
      <span className="flex items-center gap-1">
        <span className="material-symbols-rounded text-xs! text-error" aria-hidden>
          error
        </span>
        <span className="font-medium text-error">{t('failed')}</span>
        <span className="text-error">· {formatRelativeTime(testState.testedAt, locale)}</span>
      </span>
    </Tooltip>
  );
}
