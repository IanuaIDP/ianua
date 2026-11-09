'use client';

import { useEffect, useRef, useState } from 'react';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { spinnerIcon } from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { endOAuthSession, getApiErrorMessage, type TenantAuthContext } from '@/lib/api';
import type { EndSessionOutcome } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import { getTenantPath } from '@/utils/dashboard-routes';

type OAuthLogoutProps = {
  context: TenantAuthContext;
  request: Record<string, string>;
};

/** How long the apps get to hear of the sign-out in their hidden frames. */
const FRONT_CHANNEL_WAIT_MS = 1500;

/** Where an app's sign-out lands: asks first when it is unclear who is leaving. */
export function OAuthLogout({ context, request }: OAuthLogoutProps) {
  const t = useTranslations('auth.oauthLogout');
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const signOutHere = useAuthStore((state) => state.logout);
  const [result, setResult] = useState<EndSessionOutcome | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);
  const hasStarted = useRef(false);
  const signedOutPath = `${getTenantPath(context.orgSlug, context.tenantSlug)}/login`;

  useEffect(() => {
    if (!isHydrated || hasStarted.current) {
      return;
    }

    hasStarted.current = true;
    endOAuthSession(context, request, false)
      .then(setResult)
      .catch((error: unknown) => setErrorMessage(getApiErrorMessage(error, t('failed'))));
  }, [context, isHydrated, request, t]);

  useEffect(() => {
    if (result?.outcome !== 'signed_out' && result?.outcome !== 'not_signed_in') {
      return;
    }

    if (result.outcome === 'signed_out') {
      signOutHere();
    }

    const timeoutId = window.setTimeout(
      () => window.location.assign(result.redirectTo ?? signedOutPath),
      result.frontChannelLogoutUris.length > 0 ? FRONT_CHANNEL_WAIT_MS : 0,
    );

    return () => window.clearTimeout(timeoutId);
  }, [result, signOutHere, signedOutPath]);

  async function confirm() {
    setIsConfirming(true);

    try {
      setResult(await endOAuthSession(context, request, true));
    } catch (error) {
      setErrorMessage(getApiErrorMessage(error, t('failed')));
    } finally {
      setIsConfirming(false);
    }
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      {result?.outcome === 'confirm' ? (
        <AuthCard title={t('confirmTitle')} subtitle={t('confirmSubtitle')} backToLogin={false}>
          <div className="flex flex-col gap-2">
            <Button type="button" isLoading={isConfirming} onClick={() => void confirm()}>
              {t('confirm')}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={isConfirming}
              onClick={() =>
                window.location.assign(
                  result.redirectTo ?? signedOutPath.replace('/login', '/overview'),
                )
              }
            >
              {t('stay')}
            </Button>
          </div>
        </AuthCard>
      ) : errorMessage ? (
        <AuthCard title={t('failedTitle')} subtitle={errorMessage} backToLogin={false}>
          {null}
        </AuthCard>
      ) : (
        <div className="flex flex-col items-center gap-4 text-center">
          {spinnerIcon}
          <p className="text-sm font-medium text-textGray">{t('working')}</p>
        </div>
      )}
      {result?.frontChannelLogoutUris.map((uri) => (
        <iframe key={uri} src={uri} className="hidden" title={t('frameTitle')} />
      ))}
    </AuthLayout>
  );
}
