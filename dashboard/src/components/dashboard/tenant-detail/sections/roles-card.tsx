'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DeleteRoleModal } from '@/components/dashboard/tenant-detail/sections/roles/delete-role-modal';
import { RoleFormModal } from '@/components/dashboard/tenant-detail/sections/roles/role-form-modal';
import { RolesTable } from '@/components/dashboard/tenant-detail/sections/roles/roles-table';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createRole,
  deleteRole,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantResourceTypes,
  getTenantRoles,
  updateRole,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CreateRoleInput } from '@/schemas/role-schemas';
import type { Role, RoleSortField } from '@/types/role';

function toRoleFormValues(role: Role): CreateRoleInput {
  return {
    name: role.name,
    permissions: [
      ...role.systemPermissions,
      ...role.customPermissions.map((permission) => ({
        [permission.resource]: permission.action,
      })),
    ],
  };
}

export function RolesCard() {
  const t = useTranslations('dashboard.tenantRoles');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateRole = hasPermission('Roles', 'Create');
  const canUpdateRole = hasPermission('Roles', 'Update');
  const canDeleteRole = hasPermission('Roles', 'Delete');
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
  } = useTableQueryState<RoleSortField>();
  const [isCreateRoleModalOpen, setIsCreateRoleModalOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [deleteTargetRole, setDeleteTargetRole] = useState<Role | null>(null);

  const {
    data: rolesList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantRoles(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['tenant-roles', orgSlug, tenantSlug, after, rowsPerPage, sortField, sortDirection],
  });
  // Needed on submit, not for display: it is what tells a permission the
  // tenant declared from one the platform defines, and the two go to different
  // fields on the API.
  const { data: catalogue } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantResourceTypes(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-resource-types', orgSlug, tenantSlug],
  });
  const resourceTypes = catalogue?.items ?? [];

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateRoles() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-roles', orgSlug, tenantSlug] });
    await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isCreatingRole, mutate: submitCreateRole } = useMutation({
    mutationFn: (payload: CreateRoleInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createRole(orgSlug, tenantSlug, payload, resourceTypes);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsCreateRoleModalOpen(false);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateRoles();
    },
  });

  const { isPending: isUpdatingRole, mutate: submitUpdateRole } = useMutation({
    mutationFn: (payload: CreateRoleInput) => {
      if (!orgSlug || !editingRole) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateRole(
        orgSlug,
        tenantSlug,
        editingRole.id,
        payload,
        editingRole.isDefault,
        resourceTypes,
      );
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setEditingRole(null);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateRoles();
    },
  });

  const { isPending: isDeletingRole, mutate: submitDeleteRole } = useMutation({
    mutationFn: ({ role, reassignToRoleId }: { reassignToRoleId?: string; role: Role }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteRole(orgSlug, tenantSlug, role.id, reassignToRoleId);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.deleteFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setDeleteTargetRole(null);
      showNotification({ message: t('toasts.deleted'), type: 'success' });
      await invalidateRoles();
    },
  });

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
            rowsPerPageSelectId="roles-rows-per-page"
            itemCount={rolesList?.items.length ?? 0}
            nextCursor={rolesList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canCreateRole ? () => setIsCreateRoleModalOpen(true) : undefined}
      >
        <RolesTable
          canDeleteRole={canDeleteRole}
          canUpdateRole={canUpdateRole}
          isLoading={isLoading}
          roles={rolesList?.items ?? []}
          sortDirection={sortDirection}
          sortField={sortField}
          onDeleteClick={setDeleteTargetRole}
          onEditClick={setEditingRole}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <RoleFormModal
        open={isCreateRoleModalOpen}
        title={t('createModal.title')}
        description={t('createModal.description')}
        primaryActionLabel={t('create')}
        isSubmitting={isCreatingRole}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setIsCreateRoleModalOpen(false)}
        onSubmit={submitCreateRole}
      />
      <RoleFormModal
        open={Boolean(editingRole)}
        title={t('editModal.title')}
        description={t('editModal.description')}
        primaryActionLabel={t('editModal.submit')}
        defaultValues={editingRole ? toRoleFormValues(editingRole) : undefined}
        isSubmitting={isUpdatingRole}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setEditingRole(null)}
        onSubmit={submitUpdateRole}
      />
      <DeleteRoleModal
        isSubmitting={isDeletingRole}
        orgSlug={orgSlug}
        role={deleteTargetRole}
        tenantSlug={tenantSlug}
        onClose={() => setDeleteTargetRole(null)}
        onConfirm={(role, reassignToRoleId) => submitDeleteRole({ reassignToRoleId, role })}
      />
    </>
  );
}
