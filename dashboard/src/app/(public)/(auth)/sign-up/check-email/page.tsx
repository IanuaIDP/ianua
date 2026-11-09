'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { Button } from '@/components/ui/Button';
import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { CHECK_EMAIL_ALLOWED_CONTEXTS } from '@/constants/auth';
import { getTenantPath } from '@/utils/dashboard-routes';
import { RESEND_COOLDOWN_SECONDS } from '@/constants/settings';
import { getApiErrorMessage } from '@/lib/api/errors';
import {
  requestOrganizationPasswordReset,
  requestTenantPasswordReset,
} from '@/lib/api/services/auth';
import { sendOrganizationVerificationEmail } from '@/lib/api/services/team';
import { isValidEmail } from '@/lib/auth/email';
import { formatCountdown } from '@/utils/countdown';

function CheckEmailContent() {
  const t = useTranslations('auth.checkEmail');
  const router = useRouter();
  const searchParams = useSearchParams();
  const email = searchParams.get('email');
  const context = searchParams.get('context');
  const orgSlug = searchParams.get('org');
  const tenantSlug = searchParams.get('tenant');
  const tenantContext = orgSlug && tenantSlug ? { orgSlug, tenantSlug } : undefined;
  const isValidContext = Boolean(context && CHECK_EMAIL_ALLOWED_CONTEXTS.includes(context));
  const expectedGate = context && email ? `${context}:${email}` : null;
  const [isAllowed, setIsAllowed] = useState(false);
  const isSignUpContext = context === 'sign-up';
  const isTenantSignUp = isSignUpContext && Boolean(tenantContext);
  const message = isTenantSignUp
    ? t('tenantSignUpMessage', { email: email ?? '' })
    : isSignUpContext
      ? t('signUpMessage', { email: email ?? '' })
      : t('resetMessage', { email: email ?? '' });
  const [isResending, setIsResending] = useState(false);
  const [resendError, setResendError] = useState<string | null>(null);
  const [resendCooldown, setResendCooldown] = useState(RESEND_COOLDOWN_SECONDS);
  const tenantPath = tenantContext
    ? getTenantPath(tenantContext.orgSlug, tenantContext.tenantSlug)
    : undefined;
  const fallbackHref =
    context === 'reset-password'
      ? tenantPath
        ? `${tenantPath}/forgot-password`
        : '/forgot-password'
      : tenantPath
        ? `${tenantPath}/sign-up`
        : '/sign-up';

  useEffect(() => {
    if (!isValidEmail(email) || !isValidContext || !expectedGate) {
      router.replace(fallbackHref);
      return;
    }

    if (window.sessionStorage.getItem('ianua-check-email') !== expectedGate) {
      router.replace(fallbackHref);
      return;
    }

    const animationFrameId = window.requestAnimationFrame(() => setIsAllowed(true));

    return () => window.cancelAnimationFrame(animationFrameId);
  }, [email, expectedGate, fallbackHref, isValidContext, router]);

  useEffect(() => {
    if (resendCooldown <= 0) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setResendCooldown((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => window.clearTimeout(timeoutId);
  }, [resendCooldown]);

  if (!isAllowed) {
    return null;
  }

  async function handleResendEmail() {
    if (!email || resendCooldown > 0) {
      return;
    }

    setResendError(null);

    try {
      setIsResending(true);

      if (context === 'reset-password') {
        if (tenantContext) {
          await requestTenantPasswordReset(tenantContext, email);
        } else {
          await requestOrganizationPasswordReset(email);
        }
      } else if (context === 'sign-up' && orgSlug) {
        await sendOrganizationVerificationEmail(orgSlug, email);
      }

      setResendCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (error) {
      setResendError(getApiErrorMessage(error, t('resendFailed')));
    } finally {
      setIsResending(false);
    }
  }

  const backToLoginHref = tenantPath ? `${tenantPath}/login` : '/login';

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect={Boolean(tenantContext)}>
      <AuthCard
        title={t('title')}
        icon={<div className="text-[32px]">📫</div>}
        backToLoginHref={backToLoginHref}
      >
        <div className="flex flex-col items-center text-center space-y-6">
          <p className="text-sm text-textGray">{message}</p>
          {!isTenantSignUp && (
            <Button
              variant="outline"
              onClick={handleResendEmail}
              isLoading={isResending}
              disabled={resendCooldown > 0}
            >
              {isSignUpContext ? t('resendVerification') : t('resend')}
              {resendCooldown > 0 ? ` (${formatCountdown(resendCooldown)})` : ''}
            </Button>
          )}
          {resendError && (
            <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {resendError}
            </p>
          )}
        </div>
      </AuthCard>
    </AuthLayout>
  );
}

export default function CheckEmailPage() {
  return (
    <Suspense>
      <CheckEmailContent />
    </Suspense>
  );
}
