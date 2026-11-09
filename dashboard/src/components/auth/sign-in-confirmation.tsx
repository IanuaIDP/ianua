'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { MfaEnrollmentStep } from '@/components/auth/mfa-enrollment-step';
import { TenantSignInCompletion } from '@/components/auth/tenant-sign-in-completion';
import { useApplyPasskeyLogin } from '@/hooks/auth/use-apply-passkey-login';
import {
  confirmOrganizationSignIn,
  confirmTenantSignIn,
  getOrgAccess,
  type LoginResult,
  type WaitingSignIn,
} from '@/lib/api/services/auth';
import { clearWaitingSignIn, readWaitingSignIn } from '@/lib/auth/waiting-sign-in';
import { useAuthStore } from '@/store/auth-store';

type SignInConfirmationProps = {
  orgSlug: string;
  tenantSlug: string;
  token: string;
};

type Enrolling = Extract<LoginResult, { kind: 'mfa_required' | 'mfa_enrollment_required' }>;

function waitingSignInFor(orgSlug: string, tenantSlug: string): WaitingSignIn {
  const waiting = readWaitingSignIn();

  if (!waiting || waiting.orgSlug !== orgSlug || (waiting.tenantSlug ?? '') !== tenantSlug) {
    throw new Error('this browser holds no sign-in waiting for this link');
  }

  return waiting;
}

/**
 * Where the link mailed to confirm a sign-in lands. It only finishes in the
 * browser that began the sign-in, which kept it for this page.
 */
export function SignInConfirmation({ orgSlug, tenantSlug, token }: SignInConfirmationProps) {
  const t = useTranslations('auth.signInConfirmation');
  const consume = useCallback(async () => {
    const waiting = waitingSignInFor(orgSlug, tenantSlug);
    const result = await confirmTenantSignIn(
      { orgSlug, tenantSlug },
      waiting.pendingResponse,
      token,
    );

    clearWaitingSignIn();

    return result;
  }, [orgSlug, tenantSlug, token]);

  if (!tenantSlug) {
    return <OrganizationSignInConfirmation orgSlug={orgSlug} token={token} />;
  }

  return (
    <TenantSignInCompletion
      context={{ orgSlug, tenantSlug }}
      complete={orgSlug && token ? consume : null}
      failure={{ title: t('failedTitle'), subtitle: t('failedSubtitle') }}
    />
  );
}

type OrganizationSignInConfirmationProps = {
  orgSlug: string;
  token: string;
};

function OrganizationSignInConfirmation({ orgSlug, token }: OrganizationSignInConfirmationProps) {
  const t = useTranslations('auth.signInConfirmation');
  const tMagicLink = useTranslations('auth.magicLink');
  const router = useRouter();
  const applyLogin = useApplyPasskeyLogin();
  const setTokens = useAuthStore((state) => state.setTokens);
  const logout = useAuthStore((state) => state.logout);
  const [hasFailed, setHasFailed] = useState(!orgSlug || !token);
  const [enrolling, setEnrolling] = useState<Enrolling | null>(null);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (!orgSlug || !token || hasStarted.current) {
      return;
    }

    hasStarted.current = true;

    async function confirm() {
      const result = await confirmOrganizationSignIn(waitingSignInFor(orgSlug, ''), token);

      clearWaitingSignIn();

      if (result.kind === 'authenticated') {
        setTokens({ accessToken: result.response.accessToken });
        await applyLogin({ ...result.response, access: await getOrgAccess(orgSlug) });
        return;
      }

      if (result.kind !== 'mfa_enrollment_required') {
        throw new Error('an organization sign-in owes only a factor to set up here');
      }

      setTokens({ accessToken: result.pendingResponse.accessToken });
      setEnrolling(result);
    }

    confirm().catch(() => setHasFailed(true));
  }, [applyLogin, orgSlug, setTokens, token]);

  if (hasFailed) {
    return (
      <AuthCard title={t('failedTitle')} subtitle={t('failedSubtitle')}>
        {null}
      </AuthCard>
    );
  }

  if (enrolling) {
    return (
      <MfaEnrollmentStep
        orgSlug={enrolling.orgSlug}
        pendingResponse={enrolling.pendingResponse}
        sessionId={enrolling.sessionId}
        onBack={() => {
          logout();
          router.push('/login');
        }}
      />
    );
  }

  return (
    <AuthCard
      title={tMagicLink('signingInTitle')}
      subtitle={tMagicLink('signingInSubtitle')}
      backToLogin={false}
    >
      {null}
    </AuthCard>
  );
}
