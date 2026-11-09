'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { spinnerIcon } from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { finishWorkflowAccountConnection, getApiErrorMessage } from '@/lib/api';
import {
  clearAccountConnectionTarget,
  readAccountConnectionTarget,
  readConnectionReturn,
  type AccountConnectionTarget,
  type ConnectionReturn,
} from '@/lib/auth/account-connection';
import { getTenantPath } from '@/utils/dashboard-routes';

const KNOWN_ERRORS = ['declined', 'unknown', 'expired', 'unreachable', 'refused'] as const;

type KnownError = (typeof KNOWN_ERRORS)[number];

function isKnownError(error: string): error is KnownError {
  return (KNOWN_ERRORS as readonly string[]).includes(error);
}

type Outcome =
  | { kind: 'working' }
  | { kind: 'refused'; message: string }
  | { error: KnownError; kind: 'error' }
  | { kind: 'lost' };

function outcomeOf(answer: ConnectionReturn, saved: AccountConnectionTarget | null): Outcome {
  if (answer.kind === 'failed') {
    return { error: isKnownError(answer.error) ? answer.error : 'unknown', kind: 'error' };
  }

  return answer.kind === 'ready' && saved ? { kind: 'working' } : { kind: 'lost' };
}

function ConnectionResult() {
  const t = useTranslations('auth.integrationConnected');
  const router = useRouter();
  const [answer] = useState(() => readConnectionReturn(window.location.hash));
  const [target] = useState(() => readAccountConnectionTarget());
  const [refusal, setRefusal] = useState<string | null>(null);
  const hasRun = useRef(false);
  const accountsPath = target
    ? `${getTenantPath(target.orgSlug, target.tenantSlug)}/connected-accounts`
    : '/tenants';
  const outcome: Outcome = refusal
    ? { kind: 'refused', message: refusal }
    : outcomeOf(answer, target);

  useEffect(() => {
    if (hasRun.current) {
      return;
    }

    hasRun.current = true;
    window.history.replaceState(null, '', window.location.pathname);

    if (answer.kind !== 'ready' || !target) {
      return;
    }

    finishWorkflowAccountConnection(
      target.orgSlug,
      target.tenantSlug,
      answer.connectionId,
      answer.code,
    )
      .then(() => {
        clearAccountConnectionTarget();
        router.replace(accountsPath);
      })
      .catch((error: unknown) => {
        setRefusal(getApiErrorMessage(error, t('finishFailed')));
      });
  }, [accountsPath, answer, router, t, target]);

  if (outcome.kind === 'working') {
    return (
      <div className="flex flex-col items-center gap-4 text-center">
        {spinnerIcon}
        <p className="text-sm font-medium text-textGray">{t('working')}</p>
      </div>
    );
  }

  const description =
    outcome.kind === 'refused'
      ? outcome.message
      : outcome.kind === 'lost'
        ? t('lost')
        : t(`errors.${outcome.error}`);

  return (
    <AuthCard title={t('failedTitle')} subtitle={description} backToLogin={false}>
      <Button type="button" onClick={() => router.push(accountsPath)}>
        {t('tryAgain')}
      </Button>
    </AuthCard>
  );
}

/**
 * Where a service sends the browser back after signing in. The layout renders
 * this only in the browser, so the address can be read as the page opens.
 */
export function IntegrationConnected() {
  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <ConnectionResult />
    </AuthLayout>
  );
}
