'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { AddConnectionModal } from '@/components/dashboard/tenant-detail/sections/connections/add-connection-modal';
import { ConnectionsTable } from '@/components/dashboard/tenant-detail/sections/connections/connections-table';
import { DeleteConnectionModal } from '@/components/dashboard/tenant-detail/sections/connections/delete-connection-modal';
import { ScimProvisioningCard } from '@/components/dashboard/tenant-detail/sections/connections/scim-provisioning-card';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantConnection,
  deriveErrorMessage,
  executeConnectionAction,
  getApiErrorMessage,
  getTenantConnections,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { AddConnectionInput } from '@/schemas/connection-schemas';
import type { Connection, ConnectionAction, ConnectionSortField } from '@/types/connection';

export function ConnectionsCard() {
  const t = useTranslations('dashboard.connections');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateConnection = hasPermission('Federation', 'Create');
  const canUpdateConnection = hasPermission('Federation', 'Update');
  const canDeleteConnection = hasPermission('Federation', 'Delete');
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
  } = useTableQueryState<ConnectionSortField>();
  const [deleteTargetConnection, setDeleteTargetConnection] = useState<Connection | null>(null);
  const [isAddConnectionModalOpen, setIsAddConnectionModalOpen] = useState(false);

  const {
    data: connectionsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantConnections(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-connections',
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

  const { isPending: isDeletingConnection, mutate: submitDeleteConnection } = useMutation({
    mutationFn: (connection: Connection) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return executeConnectionAction(orgSlug, tenantSlug, connection, 'Delete');
    },
    onSuccess: async () => {
      setDeleteTargetConnection(null);
      showNotification({ message: t('toasts.deleted'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-connections', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.deleteFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isAddingConnection, mutate: submitAddConnection } = useMutation({
    mutationFn: (payload: AddConnectionInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantConnection(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsAddConnectionModalOpen(false);
      showNotification({ message: t('toasts.added'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-connections', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.addFailed')),
        type: 'error',
      });
    },
  });

  async function handleConnectionAction(connection: Connection, action: ConnectionAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeConnectionAction(orgSlug, tenantSlug, connection, action);
    await queryClient.invalidateQueries({ queryKey: ['tenant-connections', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <ScimProvisioningCard />

      <div className="min-h-0 flex-1">
        <DashboardDataCard
          actionLabel={t('add')}
          description={t('description')}
          errorMessage={errorMessage}
          footer={
            <DashboardPagination
              currentPage={currentPage}
              rowsPerPage={rowsPerPage}
              rowsPerPageSelectId="connections-rows-per-page"
              itemCount={connectionsList?.items.length ?? 0}
              nextCursor={connectionsList?.nextCursor ?? null}
              onNext={handleNextPage}
              onPrevious={handlePreviousPage}
              onRowsPerPageChange={handleRowsPerPageChange}
            />
          }
          title={t('title')}
          onActionClick={canCreateConnection ? () => setIsAddConnectionModalOpen(true) : undefined}
        >
          <ConnectionsTable
            canDeleteConnection={canDeleteConnection}
            canUpdateConnection={canUpdateConnection}
            connections={connectionsList?.items ?? []}
            isLoading={isLoading}
            sortDirection={sortDirection}
            sortField={sortField}
            onConnectionAction={handleConnectionAction}
            onDeleteClick={setDeleteTargetConnection}
            onSortChange={handleSortChange}
          />
        </DashboardDataCard>
      </div>

      <DeleteConnectionModal
        connection={deleteTargetConnection}
        isSubmitting={isDeletingConnection}
        onClose={() => setDeleteTargetConnection(null)}
        onConfirm={(connection) => submitDeleteConnection(connection)}
      />
      <AddConnectionModal
        isSubmitting={isAddingConnection}
        open={isAddConnectionModalOpen}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setIsAddConnectionModalOpen(false)}
        onSubmit={submitAddConnection}
      />
    </div>
  );
}
