'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { CreateTenantApiKeyModal } from '@/components/dashboard/tenant-detail/sections/api-keys/create-tenant-api-key-modal';
import { TenantApiKeysTable } from '@/components/dashboard/tenant-detail/sections/api-keys/tenant-api-keys-table';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantApiKey,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantApiKeys,
  pauseTenantApiKey,
  resumeTenantApiKey,
  revokeTenantApiKey,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CreateTenantApiKeyInput } from '@/schemas/tenant-api-key-schemas';
import type {
  CreatedTenantApiKey,
  TenantApiKey,
  TenantApiKeyAction,
  TenantApiKeySortField,
} from '@/types/tenant-api-key';

export function ApiKeysCard() {
  const t = useTranslations('dashboard.apiKeys');
  const tOrg = useTranslations('dashboard.settings.apiKeys');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateApiKey = hasPermission('ApiKeys', 'Create');
  const canRevokeApiKey = hasPermission('ApiKeys', 'Revoke');
  const canUpdateApiKey = hasPermission('ApiKeys', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<TenantApiKeySortField>();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createdApiKey, setCreatedApiKey] = useState<CreatedTenantApiKey | null>(null);

  const {
    data: apiKeysList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantApiKeys(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-api-keys',
      orgSlug,
      tenantSlug,
      after,
      rowsPerPage,
      sortField,
      sortDirection,
    ],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, tOrg('loadFailed'))],
  );

  const { isPending: isCreatingApiKey, mutate: submitCreateApiKey } = useMutation({
    mutationFn: (payload: CreateTenantApiKeyInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantApiKey(orgSlug, tenantSlug, payload);
    },
    onSuccess: async (apiKey) => {
      setIsCreateModalOpen(false);
      setCreatedApiKey(apiKey);
      showNotification({ message: tOrg('toasts.created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-api-keys', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, tOrg('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  async function handleApiKeyAction(apiKey: TenantApiKey, action: TenantApiKeyAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    const perform = {
      Pause: pauseTenantApiKey,
      Resume: resumeTenantApiKey,
      Revoke: revokeTenantApiKey,
    }[action];

    await perform(orgSlug, tenantSlug, apiKey.id);
    await queryClient.invalidateQueries({ queryKey: ['tenant-api-keys', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={tOrg('create')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="tenant-api-keys-rows-per-page"
            itemCount={apiKeysList?.items.length ?? 0}
            nextCursor={apiKeysList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={tOrg('title')}
        onActionClick={canCreateApiKey ? () => setIsCreateModalOpen(true) : undefined}
      >
        <TenantApiKeysTable
          apiKeys={apiKeysList?.items ?? []}
          canRevokeApiKey={canRevokeApiKey}
          canUpdateApiKey={canUpdateApiKey}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onApiKeyAction={handleApiKeyAction}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <CreateTenantApiKeyModal
        isSubmitting={isCreatingApiKey}
        open={isCreateModalOpen}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreateApiKey}
      />
      <MemberCreatedModal
        open={Boolean(createdApiKey)}
        title={tOrg('created.title')}
        description={tOrg('created.description')}
        fields={[
          { label: tOrg('created.keyLabel'), value: createdApiKey?.key ?? '', tooltipSide: 'left' },
        ]}
        footer={
          <div className="flex items-center gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium h-6.5 text-orange">
            <span className="material-symbols-rounded text-sm!">warning</span>
            {tOrg('created.warning')}
          </div>
        }
        onClose={() => setCreatedApiKey(null)}
      />
    </>
  );
}
