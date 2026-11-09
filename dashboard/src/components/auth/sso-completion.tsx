'use client';

import { useCallback } from 'react';
import { useTranslations } from 'next-intl';

import { TenantSignInCompletion } from '@/components/auth/tenant-sign-in-completion';
import { exchangeTenantSsoCode, type TenantAuthContext } from '@/lib/api/services/auth';
import { readSsoState } from '@/lib/auth/sso-state';

type SsoCompletionProps = {
  code: string;
  context: TenantAuthContext;
};

/**
 * Where a single sign-on lands: swaps the one-time code for the session,
 * then opens the tenant, asking for a second factor first when the identity
 * provider reported none and the workspace wants one. A code works once, so
 * the swap runs once even when React mounts the page twice.
 */
export function SsoCompletion({ code, context }: SsoCompletionProps) {
  const t = useTranslations('auth.sso');
  const exchange = useCallback(
    () => exchangeTenantSsoCode(context, code, readSsoState()),
    [code, context],
  );

  return (
    <TenantSignInCompletion
      context={context}
      complete={code ? exchange : null}
      failure={{ title: t('failedTitle'), subtitle: t('failedSubtitle') }}
    />
  );
}
