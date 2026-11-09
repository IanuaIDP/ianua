'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { GroupFormModal } from '@/components/dashboard/tenant-detail/sections/groups/group-form-modal';
import { GroupMembersModal } from '@/components/dashboard/tenant-detail/sections/groups/group-members-modal';
import { GroupRolesModal } from '@/components/dashboard/tenant-detail/sections/groups/group-roles-modal';
import { GroupsTable } from '@/components/dashboard/tenant-detail/sections/groups/groups-table';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createGroup,
  deleteGroup,
  updateGroup,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantGroups,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { GroupInput } from '@/schemas/group-schemas';
import type { Group, GroupSortField } from '@/types/group';

export function GroupsCard() {
  const t = useTranslations('dashboard.groups');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateGroup = hasPermission('Roles', 'Create');
  const canUpdateGroup = hasPermission('Roles', 'Assign');
  const canDeleteGroup = hasPermission('Roles', 'Delete');
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
  } = useTableQueryState<GroupSortField>();
  const [isCreateGroupModalOpen, setIsCreateGroupModalOpen] = useState(false);
  const [membersTargetGroup, setMembersTargetGroup] = useState<Group | null>(null);
  const [rolesTargetGroup, setRolesTargetGroup] = useState<Group | null>(null);
  const [deleteTargetGroup, setDeleteTargetGroup] = useState<Group | null>(null);
  const [editTargetGroup, setEditTargetGroup] = useState<Group | null>(null);

  const {
    data: groupsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantGroups(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['tenant-groups', orgSlug, tenantSlug, after, rowsPerPage, sortField, sortDirection],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const groups = groupsList?.items ?? [];

  async function invalidateGroups() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-groups', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isCreatingGroup, mutate: submitCreateGroup } = useMutation({
    mutationFn: (payload: GroupInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createGroup(orgSlug, tenantSlug, payload);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsCreateGroupModalOpen(false);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateGroups();
    },
  });

  const { isPending: isUpdatingGroup, mutate: submitUpdateGroup } = useMutation({
    mutationFn: (payload: GroupInput) => {
      if (!orgSlug || !editTargetGroup) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateGroup(orgSlug, tenantSlug, editTargetGroup, payload);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setEditTargetGroup(null);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateGroups();
    },
  });

  const { isPending: isDeletingGroup, mutate: submitDeleteGroup } = useMutation({
    mutationFn: (group: Group) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteGroup(orgSlug, tenantSlug, group.id);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.deleteFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setDeleteTargetGroup(null);
      showNotification({ message: t('toasts.deleted'), type: 'success' });
      await invalidateGroups();
    },
  });

  // The modals read the group out of the list, so a role bound while one is
  // open has to come back through the refreshed row rather than a stale copy.
  const liveRolesTargetGroup = rolesTargetGroup
    ? (groups.find((group) => group.id === rolesTargetGroup.id) ?? rolesTargetGroup)
    : null;

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
            rowsPerPageSelectId="groups-rows-per-page"
            itemCount={groupsList?.items.length ?? 0}
            nextCursor={groupsList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canCreateGroup ? () => setIsCreateGroupModalOpen(true) : undefined}
      >
        <GroupsTable
          canDeleteGroup={canDeleteGroup}
          canUpdateGroup={canUpdateGroup}
          groups={groups}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onDeleteClick={setDeleteTargetGroup}
          onEditClick={setEditTargetGroup}
          onMembersClick={setMembersTargetGroup}
          onRolesClick={setRolesTargetGroup}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <GroupFormModal
        description={t('createModal.description')}
        groups={groups}
        isSubmitting={isCreatingGroup}
        open={isCreateGroupModalOpen}
        primaryActionLabel={t('create')}
        title={t('createModal.title')}
        onClose={() => setIsCreateGroupModalOpen(false)}
        onSubmit={submitCreateGroup}
      />

      <GroupFormModal
        defaultValues={
          editTargetGroup
            ? { name: editTargetGroup.name, parentId: editTargetGroup.parentId ?? '' }
            : undefined
        }
        description={t('editModal.description')}
        groups={groups.filter((group) => group.id !== editTargetGroup?.id)}
        isSubmitting={isUpdatingGroup}
        open={Boolean(editTargetGroup)}
        primaryActionLabel={t('editModal.submit')}
        title={t('editModal.title')}
        onClose={() => setEditTargetGroup(null)}
        onSubmit={submitUpdateGroup}
      />

      <GroupMembersModal
        group={membersTargetGroup}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setMembersTargetGroup(null)}
      />

      <GroupRolesModal
        group={liveRolesTargetGroup}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onChanged={invalidateGroups}
        onClose={() => setRolesTargetGroup(null)}
      />

      <Modal
        open={Boolean(deleteTargetGroup)}
        onClose={() => setDeleteTargetGroup(null)}
        title={t('deleteModal.title')}
        description={
          deleteTargetGroup ? t('deleteModal.description', { name: deleteTargetGroup.name }) : ''
        }
        primaryActionLabel={t('deleteModal.submit')}
        isPrimaryActionLoading={isDeletingGroup}
        isPrimaryActionDisabled={isDeletingGroup}
        onPrimaryAction={() => {
          if (deleteTargetGroup) {
            submitDeleteGroup(deleteTargetGroup);
          }
        }}
      >
        <p className="flex items-start gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium text-orange">
          <span className="material-symbols-rounded text-sm!">warning</span>
          {t('deleteModal.warning')}
        </p>
      </Modal>
    </>
  );
}
