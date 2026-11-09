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
  UnavailableLinkScreen,
  LinkStateAction,
  ResendLinkAction,
} from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { DEFAULT_AUTH_CONFIG } from '@/constants/auth-config';
import { useResendCooldown } from '@/hooks/use-resend-cooldown';
import { getTenantPath } from '@/utils/dashboard-routes';
import type { PasswordPolicy } from '@/types/auth-config';
import {
  acceptTeamMemberInvitation,
  acceptTenantUserInvitation,
  getApiErrorMessage,
  isServiceUnavailableError,
  getTeamInvitationTokenStatus,
  getTenantInvitationTokenStatus,
  resendTeamInvitation,
  resendTenantInvitation,
} from '@/lib/api';
import { getDisplayNameFromSlug } from '@/lib/auth/slug';

type TokenState = 'checking' | 'valid' | 'expired' | 'used' | 'invalid' | 'unavailable';

function AcceptInviteContent() {
  const t = useTranslations('auth.acceptInvite');
  const tCommon = useTranslations('common');
  const router = useRouter();
  const searchParams = useSearchParams();
  const orgSlug = searchParams.get('org');
  const tenantSlug = searchParams.get('tenant');
  const token = searchParams.get('token');
  const [step, setStep] = useState<'set-password' | 'success'>('set-password');
  const [isAllowed, setIsAllowed] = useState(false);
  const [tokenState, setTokenState] = useState<TokenState>('checking');
  const [requiresPassword, setRequiresPassword] = useState(true);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy>(
    DEFAULT_AUTH_CONFIG.passwordPolicy,
  );
  const [isActivating, setIsActivating] = useState(false);
  const { cooldownSeconds, error: resendError, isResending, resend } = useResendCooldown();
  const { showNotification } = useNotification();

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

    const statusRequest = tenantSlug
      ? getTenantInvitationTokenStatus(orgSlug, tenantSlug, token).then(
          ({ passwordPolicy: policy, status }) => ({
            passwordPolicy: policy,
            requiresPassword: policy !== null,
            status,
          }),
        )
      : getTeamInvitationTokenStatus(orgSlug, token).then(({ passwordPolicy: policy, status }) => ({
          passwordPolicy: policy,
          requiresPassword: true,
          status,
        }));

    statusRequest
      .then(({ passwordPolicy: policy, requiresPassword: needsPassword, status }) => {
        if (isCancelled) {
          return;
        }

        setRequiresPassword(needsPassword);

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

  async function handleSetPassword(password: string) {
    if (!orgSlug || !token) {
      return;
    }

    if (tenantSlug) {
      await acceptTenantUserInvitation(orgSlug, tenantSlug, { password, token });
    } else {
      await acceptTeamMemberInvitation(orgSlug, { password, token });
    }

    setStep('success');
  }

  async function handleActivate() {
    if (!orgSlug || !tenantSlug || !token) {
      return;
    }

    setIsActivating(true);

    try {
      await acceptTenantUserInvitation(orgSlug, tenantSlug, { token });
      setStep('success');
    } catch (error) {
      showNotification({
        message: getApiErrorMessage(error, t('activateFailed')),
        type: 'error',
      });
    } finally {
      setIsActivating(false);
    }
  }

  async function handleResend() {
    if (!token) {
      return;
    }

    await resend(
      () =>
        orgSlug && tenantSlug
          ? resendTenantInvitation(orgSlug, tenantSlug, token)
          : resendTeamInvitation(orgSlug ?? '', token),
      t('resendFailed'),
    );
  }

  const welcomeName = getDisplayNameFromSlug(tenantSlug || orgSlug);

  if (step === 'success') {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard
          title={t('doneTitle')}
          subtitle={requiresPassword ? t('doneSubtitleWithPassword') : t('doneSubtitleActive')}
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
    return <CheckingLinkScreen title={t('checkingTitle')} />;
  }

  if (tokenState === 'expired') {
    return (
      <ExpiredLinkScreen title={t('expiredTitle')} subtitle={t('expiredSubtitle')}>
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
      <AlreadyUsedLinkScreen title={t('usedTitle')} subtitle={t('usedSubtitle')}>
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </AlreadyUsedLinkScreen>
    );
  }

  if (tokenState === 'unavailable') {
    return <UnavailableLinkScreen />;
  }

  if (tokenState === 'invalid') {
    return (
      <InvalidLinkScreen title={t('invalidTitle')}>
        <LinkStateAction label={tCommon('signIn')} onClick={() => router.push(loginHref)} />
      </InvalidLinkScreen>
    );
  }

  if (!requiresPassword) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard
          title={t('welcome', { name: welcomeName })}
          subtitle={t('activateSubtitle')}
          icon={<div className="text-[32px]">👋</div>}
          backToLogin={false}
        >
          <Button type="button" isLoading={isActivating} onClick={handleActivate}>
            {t('activateButton')}
          </Button>
        </AuthCard>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard
        title={t('welcome', { name: welcomeName })}
        subtitle={t('createPasswordSubtitle')}
        icon={<div className="text-[32px]">👋</div>}
        backToLogin={false}
      >
        <SetPasswordForm onSubmit={handleSetPassword} passwordPolicy={passwordPolicy} />
      </AuthCard>
    </AuthLayout>
  );
}

export default function AcceptInvitePage() {
  return (
    <Suspense>
      <AcceptInviteContent />
    </Suspense>
  );
}
