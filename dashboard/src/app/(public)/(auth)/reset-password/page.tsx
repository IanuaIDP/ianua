'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { SetPasswordForm } from '@/components/auth/set-password-form';
import {
  AlreadyUsedLinkScreen,
  CheckingLinkScreen,
  ExpiredLinkScreen,
  InvalidLinkScreen,
  LinkStateAction,
  ResendLinkAction,
} from '@/components/auth/token-status-screens';
import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Button } from '@/components/ui/Button';
import { DEFAULT_AUTH_CONFIG } from '@/constants/auth-config';
import { useResendCooldown } from '@/hooks/use-resend-cooldown';
import { getTenantPath } from '@/utils/dashboard-routes';
import type { PasswordPolicy } from '@/types/auth-config';
import {
  confirmOrganizationPasswordReset,
  confirmPasswordReset,
  getPasswordResetTokenStatus,
  getTenantPasswordResetTokenStatus,
  resendPasswordReset,
  resendTenantPasswordReset,
  getApiErrorMessage,
  isStepUpRequiredError,
  requestPasswordResetCode,
} from '@/lib/api';
import { useNotification } from '@/components/ui/notifications';

type TokenState = 'checking' | 'valid' | 'expired' | 'used' | 'invalid';

function ResetPasswordContent() {
  const t = useTranslations('auth.resetPassword');
  const tCommon = useTranslations('common');
  const router = useRouter();
  const searchParams = useSearchParams();
  const orgSlug = searchParams.get('org');
  const tenantSlug = searchParams.get('tenant');
  const token = searchParams.get('token');
  const isTenantReset = Boolean(orgSlug && tenantSlug);
  const [step, setStep] = useState<'set-password' | 'success'>('set-password');
  const [needsCode, setNeedsCode] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [isSendingCode, setIsSendingCode] = useState(false);
  const { showNotification } = useNotification();

  async function handleSendCode(org: string, tenant: string, linkToken: string) {
    setIsSendingCode(true);

    try {
      await requestPasswordResetCode({ orgSlug: org, tenantSlug: tenant }, linkToken);
      showNotification({ message: t('codeSent'), type: 'success' });
    } catch (error) {
      showNotification({ message: getApiErrorMessage(error, t('codeSendFailed')), type: 'error' });
    } finally {
      setIsSendingCode(false);
    }
  }
  const [breachedCount, setBreachedCount] = useState<number | null>(null);
  const [isAllowed, setIsAllowed] = useState(false);
  const [tokenState, setTokenState] = useState<TokenState>('checking');
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy>(
    DEFAULT_AUTH_CONFIG.passwordPolicy,
  );
  const { cooldownSeconds, error: resendError, isResending, resend } = useResendCooldown();

  useEffect(() => {
    if (!token) {
      const fallbackHref =
        orgSlug && tenantSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login';

      router.replace(fallbackHref);
      return;
    }

    const animationFrameId = window.requestAnimationFrame(() => setIsAllowed(true));

    return () => window.cancelAnimationFrame(animationFrameId);
  }, [orgSlug, router, tenantSlug, token]);

  const loginHref =
    isTenantReset && orgSlug && tenantSlug
      ? `${getTenantPath(orgSlug, tenantSlug)}/login`
      : '/login';

  useEffect(() => {
    if (!isAllowed || !token) {
      return;
    }

    let isCancelled = false;

    const statusRequest =
      isTenantReset && orgSlug && tenantSlug
        ? getTenantPasswordResetTokenStatus({ orgSlug, tenantSlug }, token)
        : getPasswordResetTokenStatus(token);

    statusRequest
      .then(({ passwordPolicy: policy, status }) => {
        if (isCancelled) {
          return;
        }

        if (policy) {
          setPasswordPolicy(policy);
        }

        if (status === 'Valid') {
          setTokenState('valid');
        } else if (status === 'Expired') {
          setTokenState('expired');
        } else if (status === 'AlreadyUsed') {
          setTokenState('used');
        } else {
          setTokenState('invalid');
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setTokenState('invalid');
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [isAllowed, isTenantReset, orgSlug, tenantSlug, token]);

  if (!isAllowed || !token) {
    return null;
  }

  async function handleSetPassword(password: string) {
    if (!token) {
      return;
    }

    try {
      await setNewPassword(token, password);
      setStep('success');
    } catch (error) {
      setNeedsCode(isStepUpRequiredError(error));
      throw error;
    }
  }

  async function setNewPassword(linkToken: string, password: string) {
    const code = needsCode ? mfaCode : undefined;

    if (!isTenantReset || !orgSlug || !tenantSlug) {
      await confirmOrganizationPasswordReset(linkToken, password, code);
      return;
    }

    const breach = await confirmPasswordReset({ orgSlug, tenantSlug }, linkToken, password, code);

    setBreachedCount(breach.isBreached ? (breach.occurrences ?? 0) : null);
  }

  async function handleResend() {
    if (!token) {
      return;
    }

    await resend(
      () =>
        isTenantReset && orgSlug && tenantSlug
          ? resendTenantPasswordReset({ orgSlug, tenantSlug }, token)
          : resendPasswordReset(token),
      t('resendFailed'),
    );
  }

  if (step === 'success') {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard
          title={t('doneTitle')}
          subtitle={t('doneSubtitle')}
          icon={<div className="text-[32px]">🎉</div>}
          backToLogin={false}
        >
          <div className="space-y-6">
            {breachedCount !== null ? (
              <p className="rounded-lg border border-orange/50 bg-orange/10 px-3 py-2 text-sm text-orange">
                {t('breachedWarning', { count: breachedCount })}
              </p>
            ) : null}
            <Button type="button" onClick={() => router.push(loginHref)}>
              {tCommon('signIn')}
            </Button>
          </div>
        </AuthCard>
      </AuthLayout>
    );
  }

  if (tokenState === 'checking') {
    return <CheckingLinkScreen title={t('checkingTitle')} />;
  }

  if (tokenState === 'expired') {
    return (
      <ExpiredLinkScreen subtitle={t('expiredSubtitle')}>
        <ResendLinkAction
          onResend={handleResend}
          isResending={isResending}
          cooldownSeconds={cooldownSeconds}
          error={resendError}
        />
      </ExpiredLinkScreen>
    );
  }

  if (tokenState === 'used') {
    return (
      <AlreadyUsedLinkScreen subtitle={t('usedSubtitle')}>
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </AlreadyUsedLinkScreen>
    );
  }

  if (tokenState === 'invalid') {
    return (
      <InvalidLinkScreen title={t('invalidTitle')}>
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </InvalidLinkScreen>
    );
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard
        title={t('setNewTitle')}
        subtitle={t('setNewSubtitle')}
        icon={<div className="text-[32px]">🔒</div>}
        backToLogin={false}
      >
        <SetPasswordForm
          onSubmit={handleSetPassword}
          passwordPolicy={passwordPolicy}
          requireTermsAgreement={false}
          submitErrorFallback={t('resetFailed')}
        >
          {needsCode ? (
            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-textGray">{t('codePrompt')}</span>
              <VerificationCodeInput value={mfaCode} onChange={setMfaCode} />
              {isTenantReset && orgSlug && tenantSlug && token ? (
                <button
                  type="button"
                  disabled={isSendingCode}
                  onClick={() => void handleSendCode(orgSlug, tenantSlug, token)}
                  className="self-start text-xs font-medium text-primary disabled:opacity-50"
                >
                  {t('sendCode')}
                </button>
              ) : null}
            </div>
          ) : null}
        </SetPasswordForm>
      </AuthCard>
    </AuthLayout>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordContent />
    </Suspense>
  );
}
