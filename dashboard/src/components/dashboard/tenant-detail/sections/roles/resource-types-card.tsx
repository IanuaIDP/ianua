'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { ResourceTypeFormModal } from '@/components/dashboard/tenant-detail/sections/roles/resource-type-form-modal';
import { ResourceTypesTable } from '@/components/dashboard/tenant-detail/sections/roles/resource-types-table';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  declareTenantResourceType,
  deleteTenantResourceType,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantResourceTypes,
  updateTenantResourceType,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ResourceTypeInput } from '@/schemas/resource-type-schemas';
import type { ResourceType, ResourceTypeSortField } from '@/types/resource-type';

function toFormValues(resourceType: ResourceType): ResourceTypeInput {
  return {
    actions: resourceType.actions.map((action) => ({
      displayName: action.displayName,
      implies: action.implies,
      key: action.key,
    })),
    dataClass: resourceType.dataClass,
    description: resourceType.description ?? '',
    displayName: resourceType.displayName,
    key: resourceType.key,
  };
}

/**
 * What this tenant's own application protects.
 *
 * Roles and routes pick their custom permissions from here rather than taking
 * free text, which is what stops `project:write` and `projects:write` being
 * two permissions nobody notices are meant to be one.
 */
export function ResourceTypesCard() {
  const t = useTranslations('dashboard.resources');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreate = hasPermission('Roles', 'Create');
  const canUpdate = hasPermission('Roles', 'Update');
  const canDelete = hasPermission('Roles', 'Delete');
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
  } = useTableQueryState<ResourceTypeSortField>();
  const [isDeclareModalOpen, setIsDeclareModalOpen] = useState(false);
  const [editing, setEditing] = useState<ResourceType | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ResourceType | null>(null);

  const {
    data: list,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantResourceTypes(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-resource-types',
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

  async function invalidate() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-resource-types', orgSlug, tenantSlug],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isDeclaring, mutate: submitDeclare } = useMutation({
    mutationFn: (payload: ResourceTypeInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return declareTenantResourceType(orgSlug, tenantSlug, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.declareFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.declared'), type: 'success' });
      setIsDeclareModalOpen(false);
      await invalidate();
    },
  });

  const { isPending: isUpdating, mutate: submitUpdate } = useMutation({
    mutationFn: (payload: ResourceTypeInput) => {
      if (!orgSlug || !editing) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantResourceType(orgSlug, tenantSlug, editing.id, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.saveFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.updated'), type: 'success' });
      setEditing(null);
      await invalidate();
    },
  });

  const { isPending: isDeleting, mutate: submitDelete } = useMutation({
    mutationFn: () => {
      if (!orgSlug || !deleteTarget) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteTenantResourceType(orgSlug, tenantSlug, deleteTarget.id);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.deleteFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.deleted'), type: 'success' });
      setDeleteTarget(null);
      await invalidate();
    },
  });

  return (
    <>
      <DashboardDataCard
        actionLabel={t('add')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="tenant-resource-types-rows-per-page"
            itemCount={list?.items.length ?? 0}
            nextCursor={list?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canCreate ? () => setIsDeclareModalOpen(true) : undefined}
      >
        <ResourceTypesTable
          canDelete={canDelete}
          canUpdate={canUpdate}
          isLoading={isLoading}
          resourceTypes={list?.items ?? []}
          sortDirection={sortDirection}
          sortField={sortField}
          onDeleteClick={setDeleteTarget}
          onEditClick={setEditing}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <ResourceTypeFormModal
        description={t('addModal.description')}
        isSubmitting={isDeclaring}
        open={isDeclareModalOpen}
        primaryActionLabel={t('addModal.submit')}
        title={t('add')}
        onClose={() => setIsDeclareModalOpen(false)}
        onSubmit={(payload) => submitDeclare(payload)}
      />

      <ResourceTypeFormModal
        defaultValues={editing ? toFormValues(editing) : undefined}
        description={t('editModal.description')}
        isKeyLocked
        isSubmitting={isUpdating}
        open={Boolean(editing)}
        primaryActionLabel={t('editModal.submit')}
        title={t('editModal.title')}
        onClose={() => setEditing(null)}
        onSubmit={(payload) => submitUpdate(payload)}
      />

      <Modal
        open={Boolean(deleteTarget)}
        title={t('deleteModal.title')}
        description={t('deleteModal.description', { key: deleteTarget?.key ?? '' })}
        primaryActionLabel={t('deleteModal.submit')}
        isPrimaryActionLoading={isDeleting}
        isPrimaryActionDisabled={isDeleting}
        onClose={() => setDeleteTarget(null)}
        onPrimaryAction={() => submitDelete()}
      >
        <p className="text-xs text-textGray">{t('deleteModal.note')}</p>
      </Modal>
    </>
  );
}
