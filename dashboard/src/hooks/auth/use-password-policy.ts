'use client';

import { useQuery } from '@tanstack/react-query';

import { getAuthConfig } from '@/lib/api/services/auth-config';
import { getOrgAuthConfig } from '@/lib/api/services/org-auth-config';
import { DEFAULT_AUTH_CONFIG, DEFAULT_ORG_AUTH_CONFIG } from '@/constants/auth-config';
import type { PasswordPolicy } from '@/types/auth-config';

export function useOrgPasswordPolicy(orgSlug: string | undefined): PasswordPolicy {
  const { data } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getOrgAuthConfig(orgSlug ?? ''),
    queryKey: ['org-auth-config', orgSlug],
  });

  return data?.passwordPolicy ?? DEFAULT_ORG_AUTH_CONFIG.passwordPolicy;
}

export function useTenantPasswordPolicy(
  orgSlug: string | undefined,
  tenantSlug: string,
): PasswordPolicy {
  const { data } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getAuthConfig(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-auth-config', orgSlug, tenantSlug],
  });

  return data?.passwordPolicy ?? DEFAULT_AUTH_CONFIG.passwordPolicy;
}
