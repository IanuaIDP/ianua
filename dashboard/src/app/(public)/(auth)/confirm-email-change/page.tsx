'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import {
  CheckingLinkScreen,
  ExpiredLinkScreen,
  InvalidLinkScreen,
  UnavailableLinkScreen,
  LinkStateAction,
  ResendLinkAction,
} from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useResendCooldown } from '@/hooks/use-resend-cooldown';
import { getTenantPath } from '@/utils/dashboard-routes';
import {
  confirmOrganizationEmailChange,
  getApiErrorMessage,
  isServiceUnavailableError,
  getOrganizationEmailChangeTokenStatus,
  getTenantEmailChangeTokenStatus,
  resendOrganizationEmailChange,
  resendTenantEmailChange,
  confirmTenantEmailChange,
} from '@/lib/api';

type TokenState = 'checking' | 'valid' | 'expired' | 'invalid' | 'unavailable';

function ConfirmEmailChangeContent() {
  const t = useTranslations('auth.confirmEmailChange');
  const tCommon = useTranslations('common');
  const router = useRouter();
  const searchParams = useSearchParams();
  const { showNotification } = useNotification();
  const orgSlug = searchParams.get('org');
  const tenantSlug = searchParams.get('tenant');
  const token = searchParams.get('token');
  const [isVerified, setIsVerified] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAllowed, setIsAllowed] = useState(false);
  const [tokenState, setTokenState] = useState<TokenState>('checking');
  const { cooldownSeconds, error: resendError, isResending, resend } = useResendCooldown();

  useEffect(() => {
    if (!orgSlug || !token) {
      const fallbackHref =
        orgSlug && tenantSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login';
      router.replace(fallbackHref);
      return;
    }

    const animationFrameId = window.requestAnimationFrame(() => setIsAllowed(true));

    return () => window.cancelAnimationFrame(animationFrameId);
  }, [orgSlug, router, tenantSlug, token]);

  const loginHref =
    tenantSlug && orgSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login';

  useEffect(() => {
    if (!isAllowed || !orgSlug || !token) {
      return;
    }

    let isCancelled = false;

    const statusRequest =
      orgSlug && tenantSlug
        ? getTenantEmailChangeTokenStatus(orgSlug, tenantSlug, token)
        : getOrganizationEmailChangeTokenStatus(orgSlug, token);

    statusRequest
      .then((status) => {
        if (isCancelled) {
          return;
        }

        if (status === 'Valid') {
          setTokenState('valid');
        } else if (status === 'Expired') {
          setTokenState('expired');
        } else {
          setTokenState('invalid');
        }
      })
      .catch((error: unknown) => {
        if (!isCancelled) {
          setTokenState(isServiceUnavailableError(error) ? 'unavailable' : 'invalid');
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [isAllowed, orgSlug, tenantSlug, token]);

  if (!isAllowed || !orgSlug || !token) {
    return null;
  }

  async function handleVerify() {
    if (!orgSlug || !token) {
      return;
    }
    setIsSubmitting(true);

    try {
      if (tenantSlug) {
        await confirmTenantEmailChange(orgSlug, tenantSlug, token);
      } else {
        await confirmOrganizationEmailChange(orgSlug, token);
      }
      setIsVerified(true);
    } catch (error) {
      showNotification({
        message: getApiErrorMessage(error, t('verifyFailed')),
        type: 'error',
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleResend() {
    if (!token) {
      return;
    }

    await resend(
      () =>
        orgSlug && tenantSlug
          ? resendTenantEmailChange(orgSlug, tenantSlug, token)
          : resendOrganizationEmailChange(orgSlug ?? '', token),
      t('resendFailed'),
    );
  }

  if (isVerified) {
    return (
      <AuthLayout showBtn={false} showFooter>
        <AuthCard
          title={t('verifiedTitle')}
          subtitle={t('verifiedSubtitle')}
          icon={<div className="text-[32px]">🎉</div>}
          backToLogin={false}
        >
          <Button type="button" onClick={() => router.push(loginHref)}>
            {tCommon('signIn')}
          </Button>
        </AuthCard>
      </AuthLayout>
    );
  }

  if (tokenState === 'checking') {
    return <CheckingLinkScreen />;
  }

  if (tokenState === 'expired') {
    return (
      <ExpiredLinkScreen>
        <ResendLinkAction
          onResend={handleResend}
          isResending={isResending}
          cooldownSeconds={cooldownSeconds}
          error={resendError}
        />
      </ExpiredLinkScreen>
    );
  }

  if (tokenState === 'unavailable') {
    return <UnavailableLinkScreen />;
  }

  if (tokenState === 'invalid') {
    return (
      <InvalidLinkScreen>
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </InvalidLinkScreen>
    );
  }

  if (isSubmitting) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard
          title={t('verifyingTitle')}
          subtitle={t('verifyingSubtitle')}
          icon={
            <span className="material-symbols-rounded animate-spin text-[32px] text-primary">
              progress_activity
            </span>
          }
          backToLogin={false}
        >
          <></>
        </AuthCard>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard
        title={t('verifyTitle')}
        subtitle={t('verifySubtitle')}
        icon={<span className="text-[32px]">✉️</span>}
        backToLogin={false}
      >
        <Button type="button" isLoading={isSubmitting} onClick={handleVerify}>
          {t('verifyButton')}
        </Button>
      </AuthCard>
    </AuthLayout>
  );
}

export default function ConfirmEmailChangePage() {
  return (
    <Suspense>
      <ConfirmEmailChangeContent />
    </Suspense>
  );
}
