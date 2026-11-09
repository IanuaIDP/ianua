'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import {
  AlreadyUsedLinkScreen,
  CheckingLinkScreen,
  ExpiredLinkScreen,
  InvalidLinkScreen,
  LinkStateAction,
  ResendLinkAction,
} from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useResendCooldown } from '@/hooks/use-resend-cooldown';
import { getTenantPath } from '@/utils/dashboard-routes';
import {
  getApiErrorMessage,
  getTenantVerificationTokenStatus,
  getVerificationTokenStatus,
  resendVerificationEmail,
  verifyOrganizationUserEmail,
  verifyTenantUserEmail,
} from '@/lib/api';

type TokenStatus = 'checking' | 'expired' | 'invalid' | 'valid' | 'verified';

const spinnerIcon = (
  <span className="material-symbols-rounded animate-spin text-[32px] text-primary">
    progress_activity
  </span>
);

function VerifyEmailContent() {
  const t = useTranslations('auth.verifyEmail');
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
  const [tokenStatus, setTokenStatus] = useState<TokenStatus>('checking');
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
    orgSlug && tenantSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login';

  useEffect(() => {
    if (!isAllowed || !orgSlug || !token) {
      return;
    }

    let isCancelled = false;

    const statusRequest = tenantSlug
      ? getTenantVerificationTokenStatus(orgSlug, tenantSlug, token)
      : getVerificationTokenStatus(token);

    statusRequest
      .then((status) => {
        if (isCancelled) {
          return;
        }

        if (status === 'Verified') {
          setTokenStatus('verified');
        } else if (status === 'Expired') {
          setTokenStatus('expired');
        } else {
          setTokenStatus('valid');
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setTokenStatus('invalid');
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
        await verifyTenantUserEmail(orgSlug, tenantSlug, token);
      } else {
        await verifyOrganizationUserEmail(orgSlug, token);
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

  async function handleResendVerification() {
    if (!token) {
      return;
    }

    await resend(() => resendVerificationEmail(token), t('resendFailed'));
  }

  if (tokenStatus === 'checking') {
    return <CheckingLinkScreen title={t('checkingTitle')} />;
  }

  if (isVerified) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
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

  if (tokenStatus === 'verified') {
    return (
      <AlreadyUsedLinkScreen
        title={t('alreadyVerifiedTitle')}
        subtitle={t('alreadyVerifiedSubtitle')}
      >
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </AlreadyUsedLinkScreen>
    );
  }

  if (tokenStatus === 'expired') {
    return (
      <ExpiredLinkScreen title={t('expiredTitle')} subtitle={t('expiredSubtitle')}>
        <ResendLinkAction
          onResend={handleResendVerification}
          isResending={isResending}
          cooldownSeconds={cooldownSeconds}
          error={resendError}
        />
      </ExpiredLinkScreen>
    );
  }

  if (tokenStatus === 'invalid') {
    return (
      <InvalidLinkScreen title={t('invalidTitle')}>
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
          icon={spinnerIcon}
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

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailContent />
    </Suspense>
  );
}
