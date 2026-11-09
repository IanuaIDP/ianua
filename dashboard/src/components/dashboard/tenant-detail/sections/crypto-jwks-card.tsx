'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { CryptoJwksTable } from '@/components/dashboard/tenant-detail/sections/crypto/crypto-jwks-table';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { deriveErrorMessage, getApiErrorMessage, getTenantJwksKeys } from '@/lib/api';

export function CryptoJwksCard() {
  const t = useTranslations('dashboard.crypto.jwks');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { canView, isLoading: isLoadingPermissions } = useTenantPermissions();
  const canViewCrypto = canView('Crypto');

  const {
    data: keys,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && canViewCrypto),
    queryFn: () => getTenantJwksKeys(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-jwks-keys', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [!isLoadingPermissions && !canViewCrypto, t('noPermission')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  return (
    <DashboardDataCard
      description={t('description')}
      errorMessage={errorMessage}
      title={t('title')}
    >
      <CryptoJwksTable keys={keys ?? []} isLoading={isLoading || isLoadingPermissions} />
    </DashboardDataCard>
  );
}
