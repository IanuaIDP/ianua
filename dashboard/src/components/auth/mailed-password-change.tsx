'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { DuePasswordChangeStep } from '@/components/auth/due-password-change-step';
import { useApplyTenantPasskeyLogin } from '@/hooks/auth/use-apply-tenant-passkey-login';
import type { LoginResult } from '@/lib/api/services/auth';
import { getTenantPath } from '@/utils/dashboard-routes';

type MailedPasswordChangeProps = {
  orgSlug: string;
  tenantSlug: string;
  token: string;
};

/** Where the link mailed for a password that must change lands. */
export function MailedPasswordChange({ orgSlug, tenantSlug, token }: MailedPasswordChangeProps) {
  const t = useTranslations('auth.duePasswordChange');
  const router = useRouter();
  const tenantPath = getTenantPath(orgSlug, tenantSlug);
  const loginPath = `${tenantPath}/login`;
  const applyLogin = useApplyTenantPasskeyLogin({ redirectTo: `${tenantPath}/overview` });

  if (!orgSlug || !tenantSlug || !token) {
    return (
      <AuthCard title={t('invalidTitle')} subtitle={t('invalidSubtitle')}>
        {null}
      </AuthCard>
    );
  }

  function carryOn(result: LoginResult) {
    if (result.kind === 'authenticated') {
      void applyLogin(result.response);
      return;
    }

    router.push(loginPath);
  }

  return (
    <DuePasswordChangeStep
      changeToken={token}
      context={{ orgSlug, tenantSlug }}
      email=""
      proof="none"
      onBack={() => router.push(loginPath)}
      onContinue={carryOn}
    />
  );
}
