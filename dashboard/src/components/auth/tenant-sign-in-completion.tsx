'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { MfaEnrollmentStep } from '@/components/auth/mfa-enrollment-step';
import { MfaVerificationStep } from '@/components/auth/mfa-verification-step';
import { useApplyTenantPasskeyLogin } from '@/hooks/auth/use-apply-tenant-passkey-login';
import type { LoginResult, TenantAuthContext } from '@/lib/api/services/auth';
import { useAuthStore } from '@/store/auth-store';
import { getTenantPath } from '@/utils/dashboard-routes';

type TenantSignInCompletionProps = {
  context: TenantAuthContext;
  /** Finishes the sign-in. Runs once, even when React mounts the page twice. */
  complete: (() => Promise<LoginResult>) | null;
  /** What the page says when the sign-in cannot finish. */
  failure: { title: string; subtitle: string };
};

type Pending = Extract<LoginResult, { sessionId: string; tenantSlug: string }>;

/**
 * Where a sign-in that left the sign-in page lands, such as an emailed link
 * or a single sign-on: finishes it, then opens the tenant, asking for a
 * second factor first when the workspace wants one.
 */
export function TenantSignInCompletion({
  context,
  complete,
  failure,
}: TenantSignInCompletionProps) {
  const t = useTranslations('auth.magicLink');
  const router = useRouter();
  const tenantPath = getTenantPath(context.orgSlug, context.tenantSlug);
  const loginPath = `${tenantPath}/login`;
  const redirectTo = `${tenantPath}/overview`;
  const applyLogin = useApplyTenantPasskeyLogin({ redirectTo });
  const setTokens = useAuthStore((state) => state.setTokens);
  const logout = useAuthStore((state) => state.logout);
  const [hasFailed, setHasFailed] = useState(!complete);
  const [pending, setPending] = useState<Pending | null>(null);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (!complete || hasStarted.current) {
      return;
    }

    hasStarted.current = true;
    complete()
      .then(async (result) => {
        if (result.kind === 'authenticated') {
          await applyLogin(result.response);
          return;
        }

        if (
          result.kind === 'email_confirmation_required' ||
          result.kind === 'choose_organization' ||
          result.kind === 'password_change_required' ||
          !('tenantSlug' in result)
        ) {
          throw new Error('an organization sign-in cannot finish on a workspace page');
        }

        setTokens({ accessToken: result.pendingResponse.accessToken });
        setPending(result);
      })
      .catch(() => setHasFailed(true));
  }, [applyLogin, complete, setTokens]);

  function startOver() {
    logout();
    router.push(loginPath);
  }

  if (hasFailed) {
    return (
      <AuthCard title={failure.title} subtitle={failure.subtitle} backToLoginHref={loginPath}>
        {null}
      </AuthCard>
    );
  }

  if (pending?.kind === 'tenant_mfa_enrollment_required') {
    return (
      <MfaEnrollmentStep
        orgSlug={context.orgSlug}
        tenantSlug={context.tenantSlug}
        pendingResponse={pending.pendingResponse}
        redirectTo={redirectTo}
        sessionId={pending.sessionId}
        onBack={startOver}
      />
    );
  }

  if (pending) {
    return (
      <MfaVerificationStep
        orgSlug={context.orgSlug}
        pendingResponse={pending.pendingResponse}
        redirectTo={redirectTo}
        sessionId={pending.sessionId}
        tenantSlug={context.tenantSlug}
        onBack={startOver}
      />
    );
  }

  return (
    <AuthCard title={t('signingInTitle')} subtitle={t('signingInSubtitle')} backToLogin={false}>
      {null}
    </AuthCard>
  );
}
