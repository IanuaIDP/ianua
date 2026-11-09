'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { MfaEnrollmentStep } from '@/components/auth/mfa-enrollment-step';
import { MfaVerificationStep } from '@/components/auth/mfa-verification-step';
import { useApplyPasskeyLogin } from '@/hooks/auth/use-apply-passkey-login';
import { finishOrganizationSso, type LoginResult, type OrgSsoAnswer } from '@/lib/api';
import { readOrgSsoBinding, readOrgSsoSamlAnswer } from '@/lib/auth/org-sso';
import { useAuthStore } from '@/store/auth-store';

type Pending = Extract<LoginResult, { kind: 'mfa_enrollment_required' | 'mfa_required' }>;

type OrgSsoCompletionProps = {
  /** The answer from a redirect; a SAML answer waits in session storage instead. */
  oidcAnswer?: { code: string; state: string };
};

/** Finishes a dashboard sign-in through the organization's identity provider. */
export function OrgSsoCompletion({ oidcAnswer }: OrgSsoCompletionProps) {
  const t = useTranslations('auth.orgSso');
  const router = useRouter();
  const applyLogin = useApplyPasskeyLogin();
  const setTokens = useAuthStore((state) => state.setTokens);
  const logout = useAuthStore((state) => state.logout);
  const [pending, setPending] = useState<Pending | null>(null);
  const [hasFailed, setHasFailed] = useState(false);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (hasStarted.current) {
      return;
    }

    hasStarted.current = true;

    const answer: OrgSsoAnswer | null = oidcAnswer
      ? { code: oidcAnswer.code, protocol: 'oidc', state: oidcAnswer.state }
      : readOrgSsoSamlAnswer();
    const binding = readOrgSsoBinding();

    Promise.resolve()
      .then(() => {
        if (!answer || !binding) {
          throw new Error('no single sign-on in progress');
        }

        return finishOrganizationSso(binding, answer);
      })
      .then(async (result) => {
        if (result.kind === 'authenticated') {
          await applyLogin(result.response);
          return;
        }

        if (result.kind === 'mfa_required' || result.kind === 'mfa_enrollment_required') {
          setTokens({ accessToken: result.pendingResponse.accessToken });
          setPending(result);
          return;
        }

        setHasFailed(true);
      })
      .catch(() => setHasFailed(true));
  }, [applyLogin, oidcAnswer, setTokens]);

  function startOver() {
    logout();
    router.push('/login');
  }

  if (hasFailed) {
    return (
      <AuthCard title={t('failedTitle')} subtitle={t('failedSubtitle')}>
        {null}
      </AuthCard>
    );
  }

  if (pending?.kind === 'mfa_enrollment_required') {
    return (
      <MfaEnrollmentStep
        orgSlug={pending.orgSlug}
        pendingResponse={pending.pendingResponse}
        sessionId={pending.sessionId}
        onBack={startOver}
      />
    );
  }

  if (pending) {
    return (
      <MfaVerificationStep
        orgSlug={pending.orgSlug}
        pendingResponse={pending.pendingResponse}
        sessionId={pending.sessionId}
        onBack={startOver}
      />
    );
  }

  return (
    <AuthCard title={t('workingTitle')} subtitle={t('workingSubtitle')} backToLogin={false}>
      {null}
    </AuthCard>
  );
}
