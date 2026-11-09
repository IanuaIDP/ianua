'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { OAuthClientFormModal } from '@/components/dashboard/tenant-detail/sections/oauth-clients/oauth-client-form-modal';
import { OAuthClientsTable } from '@/components/dashboard/tenant-detail/sections/oauth-clients/oauth-clients-table';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantOAuthClient,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantOAuthClients,
  parseRedirectUris,
  revokeTenantOAuthClient,
  rotateTenantOAuthClientSecret,
  updateTenantOAuthClient,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { OAuthClientFormInput } from '@/schemas/oauth-client-schemas';
import type {
  CreatedOAuthClient,
  OAuthClient,
  OAuthClientAction,
  OAuthClientSortField,
} from '@/types/oauth-client';

export function OAuthClientsCard() {
  const t = useTranslations('dashboard.oauthClients');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateClient = hasPermission('ApiKeys', 'Create');
  const canUpdateClient = hasPermission('ApiKeys', 'Update');
  const canRevokeClient = hasPermission('ApiKeys', 'Revoke');
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
  } = useTableQueryState<OAuthClientSortField>();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [editingClient, setEditingClient] = useState<OAuthClient | null>(null);
  const [createdClient, setCreatedClient] = useState<CreatedOAuthClient | null>(null);
  const [isSecretRotated, setIsSecretRotated] = useState(false);

  const {
    data: clientsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantOAuthClients(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-oauth-clients',
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
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateClients() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-oauth-clients', orgSlug, tenantSlug],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isCreatingClient, mutate: submitCreateClient } = useMutation({
    mutationFn: (payload: OAuthClientFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantOAuthClient(orgSlug, tenantSlug, {
        name: payload.name,
        redirectUris: parseRedirectUris(payload.redirectUris),
      });
    },
    onSuccess: async (client) => {
      setIsCreateModalOpen(false);
      setIsSecretRotated(false);
      setCreatedClient(client);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateClients();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdatingClient, mutate: submitUpdateClient } = useMutation({
    mutationFn: (payload: OAuthClientFormInput) => {
      if (!orgSlug || !editingClient) {
        throw new Error(tErrors('organizationMissing'));
      }

      const redirectUris = parseRedirectUris(payload.redirectUris);

      return updateTenantOAuthClient(orgSlug, tenantSlug, editingClient.id, {
        name: payload.name,
        redirectUris: redirectUris.length > 0 ? redirectUris : null,
      });
    },
    onSuccess: async () => {
      setEditingClient(null);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateClients();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  async function handleClientAction(client: OAuthClient, action: OAuthClientAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    if (action === 'Rotate secret') {
      const clientSecret = await rotateTenantOAuthClientSecret(orgSlug, tenantSlug, client.id);
      setIsSecretRotated(true);
      setCreatedClient({ clientId: client.clientId, clientSecret });
      await invalidateClients();
      return;
    }

    if (action === 'Revoke') {
      await revokeTenantOAuthClient(orgSlug, tenantSlug, client.id);
      await invalidateClients();
    }
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('create')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="tenant-oauth-clients-rows-per-page"
            itemCount={clientsList?.items.length ?? 0}
            nextCursor={clientsList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canCreateClient ? () => setIsCreateModalOpen(true) : undefined}
      >
        <OAuthClientsTable
          canRevokeClient={canRevokeClient}
          canUpdateClient={canUpdateClient}
          clients={clientsList?.items ?? []}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onClientAction={handleClientAction}
          onEditClick={setEditingClient}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <OAuthClientFormModal
        open={isCreateModalOpen}
        title={t('createModal.title')}
        description={t('createModal.description')}
        primaryActionLabel={t('createModal.submit')}
        isSubmitting={isCreatingClient}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreateClient}
      />
      <OAuthClientFormModal
        open={Boolean(editingClient)}
        title={t('editModal.title')}
        description={t('editModal.description')}
        primaryActionLabel={t('editModal.submit')}
        defaultValues={
          editingClient
            ? {
                name: editingClient.name,
                redirectUris: editingClient.redirectUris.join('\n'),
              }
            : undefined
        }
        isSubmitting={isUpdatingClient}
        onClose={() => setEditingClient(null)}
        onSubmit={submitUpdateClient}
      />
      <MemberCreatedModal
        open={Boolean(createdClient)}
        title={isSecretRotated ? t('rotate.done') : t('created.title')}
        description={t('created.description')}
        fields={[
          {
            label: t('created.clientId'),
            value: createdClient?.clientId ?? '',
            tooltipSide: 'left',
          },
          {
            label: t('created.clientSecret'),
            value: createdClient?.clientSecret ?? '',
            tooltipSide: 'left',
          },
        ]}
        footer={
          <div className="flex items-center gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium h-6.5 text-orange">
            <span className="material-symbols-rounded text-sm!">warning</span>
            {t('created.warning')}
          </div>
        }
        onClose={() => setCreatedClient(null)}
      />
    </>
  );
}
