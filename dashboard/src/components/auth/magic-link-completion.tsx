'use client';

import { useCallback } from 'react';
import { useTranslations } from 'next-intl';

import { TenantSignInCompletion } from '@/components/auth/tenant-sign-in-completion';
import { consumeTenantMagicLink } from '@/lib/api/services/auth';

type MagicLinkCompletionProps = {
  orgSlug: string;
  tenantSlug: string;
  token: string;
};

/**
 * Where an emailed sign-in link lands: uses the link, then opens the tenant,
 * asking for a second factor first when the workspace wants one. A link works
 * once, so it is used once even when React mounts the page twice.
 */
export function MagicLinkCompletion({ orgSlug, tenantSlug, token }: MagicLinkCompletionProps) {
  const t = useTranslations('auth.magicLink');
  const consume = useCallback(
    () => consumeTenantMagicLink({ orgSlug, tenantSlug }, token),
    [orgSlug, tenantSlug, token],
  );

  return (
    <TenantSignInCompletion
      context={{ orgSlug, tenantSlug }}
      complete={orgSlug && tenantSlug && token ? consume : null}
      failure={{ title: t('failedTitle'), subtitle: t('failedSubtitle') }}
    />
  );
}
