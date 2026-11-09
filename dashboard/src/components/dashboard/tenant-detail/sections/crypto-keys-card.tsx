'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { CryptoKeysTable } from '@/components/dashboard/tenant-detail/sections/crypto/crypto-keys-table';
import { RotateCryptoKeyModal } from '@/components/dashboard/tenant-detail/sections/crypto/rotate-crypto-key-modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantCryptoKeys,
  rotateTenantCryptoKey,
  revokeTenantCryptoKey,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { RotateCryptoKeyInput } from '@/schemas/crypto-schemas';
import type { CryptoKey, CryptoKeyAction } from '@/types/crypto';

export function CryptoKeysCard() {
  const t = useTranslations('dashboard.crypto.keys');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { canView, hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const canViewCrypto = canView('Crypto');
  const canUpdateCrypto = hasPermission('Crypto', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isRotateModalOpen, setIsRotateModalOpen] = useState(false);

  const {
    data: keysList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && canViewCrypto),
    queryFn: () => getTenantCryptoKeys(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [!isLoadingPermissions && !canViewCrypto, t('noPermission')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { mutateAsync: submitKeyAction } = useMutation({
    mutationFn: async ({
      action,
      cryptoKey,
    }: {
      action: CryptoKeyAction;
      cryptoKey: CryptoKey;
    }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (action === 'Revoke') {
        await revokeTenantCryptoKey(orgSlug, tenantSlug, cryptoKey.id);
      }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { isPending: isRotatingKey, mutate: submitRotateKey } = useMutation({
    mutationFn: (payload: RotateCryptoKeyInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return rotateTenantCryptoKey(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsRotateModalOpen(false);
      showNotification({ message: t('toasts.rotated'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.rotateFailed')),
        type: 'error',
      });
    },
  });

  function handleKeyAction(cryptoKey: CryptoKey, action: CryptoKeyAction) {
    return submitKeyAction({ action, cryptoKey });
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('rotate')}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={canUpdateCrypto ? () => setIsRotateModalOpen(true) : undefined}
      >
        <CryptoKeysTable
          canRevokeKey={canUpdateCrypto}
          cryptoKeys={keysList ?? []}
          isLoading={isLoading || isLoadingPermissions}
          onKeyAction={handleKeyAction}
        />
      </DashboardDataCard>

      <RotateCryptoKeyModal
        isSubmitting={isRotatingKey}
        open={isRotateModalOpen}
        onClose={() => setIsRotateModalOpen(false)}
        onSubmit={submitRotateKey}
      />
    </>
  );
}
