'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTabs } from '@/components/dashboard/shared/dashboard-tabs';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { ResetMemberPasswordModal } from '@/components/dashboard/shared/reset-member-password-modal';
import { AddTenantUserModal } from '@/components/dashboard/tenant-detail/sections/tenant-users/add-tenant-user-modal';
import { EditUserFieldsModal } from '@/components/dashboard/tenant-detail/sections/tenant-users/edit-user-fields-modal';
import { TenantUsersTable } from '@/components/dashboard/tenant-detail/sections/tenant-users/tenant-users-table';
import { ManageUserFields } from '@/components/dashboard/tenant-detail/sections/user-attributes/manage-user-fields';
import { useNotification } from '@/components/ui/notifications';
import { getTenantPath } from '@/utils/dashboard-routes';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPasswordPolicy } from '@/hooks/auth/use-password-policy';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  assignTenantRole,
  createTenantUser,
  deriveErrorMessage,
  executeTenantUserAction,
  getApiErrorMessage,
  getTenantRoles,
  getTenantUsers,
  getUserAttributes,
  inviteTenantUser,
  resetTenantUserPassword,
  unassignTenantRole,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { AddTenantUserInput } from '@/schemas/tenant-user-schemas';
import type { ResetPasswordInput } from '@/schemas/reset-password-schema';
import { useAuthStore } from '@/store/auth-store';
import type { CreatedMemberCredentials } from '@/types/member';
import type {
  TenantUser,
  TenantUserAction,
  TenantUserSortField,
  TenantUserTab,
} from '@/types/tenant-user';

const tenantUsersTabs: TenantUserTab[] = [
  'All',
  'Active',
  'Locked',
  'Invited',
  'PendingVerification',
  'InvitationExpired',
];

export function TenantUsersCard() {
  const t = useTranslations('dashboard.tenantUsers');
  const tErrors = useTranslations('common.errors');
  const currentUserEmail = useAuthStore((state) => state.user?.email);
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const passwordPolicy = useTenantPasswordPolicy(orgSlug, tenantSlug);
  const { hasPermission } = useTenantPermissions();
  const canCreateUser = hasPermission('Users', 'Create');
  const canUpdateUser = hasPermission('Users', 'Update');
  const canDeactivateUser = hasPermission('Users', 'Deactivate');
  const canDeleteUser = hasPermission('Users', 'Delete');
  const canAssignRoles = hasPermission('Roles', 'Assign') || hasPermission('Users', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [activeTab, setActiveTab] = useState<TenantUserTab>('All');
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    resetToFirstPage,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<TenantUserSortField>();
  const [isAddUserModalOpen, setIsAddUserModalOpen] = useState(false);
  const [isManageFieldsOpen, setIsManageFieldsOpen] = useState(false);
  const [editFieldsUser, setEditFieldsUser] = useState<TenantUser | null>(null);
  const [createdUserCredentials, setCreatedUserCredentials] =
    useState<CreatedMemberCredentials | null>(null);
  const [resetPasswordUser, setResetPasswordUser] = useState<TenantUser | null>(null);
  const [invitationLink, setInvitationLink] = useState<{ email: string; link: string } | null>(
    null,
  );
  const [resetPasswordCredentials, setResetPasswordCredentials] =
    useState<CreatedMemberCredentials | null>(null);
  const status = activeTab === 'All' ? undefined : activeTab;

  // The tenant's own fields. Only the ones marked for listing become columns,
  // and the API already leaves out anything this caller may not read.
  const { data: attributes = [] } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getUserAttributes(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-user-attributes', orgSlug, tenantSlug, false],
  });
  const attributeColumns = attributes.filter((attribute) => attribute.listed);

  const {
    data: usersList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantUsers(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
        status,
      }),
    queryKey: [
      'tenant-users',
      orgSlug,
      tenantSlug,
      status,
      sortField,
      sortDirection,
      after,
      rowsPerPage,
    ],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { data: roles = [] } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: async () => {
      const response = await getTenantRoles(orgSlug ?? '', tenantSlug, { limit: 100 });

      return response.items;
    },
    queryKey: ['tenant-roles', orgSlug, tenantSlug, 'options'],
  });
  const roleOptions = roles.map((role) => ({ label: role.name, value: role.id }));

  const {
    isPending: isAddingUser,
    mutate: submitAddUser,
    reset: resetAddUserMutation,
  } = useMutation({
    mutationFn: async (payload: AddTenantUserInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (payload.mode === 'create') {
        const created = await createTenantUser(orgSlug, tenantSlug, payload);

        return { created, inviteLink: null };
      }

      const invited = await inviteTenantUser(orgSlug, tenantSlug, payload);

      // An invitation names one role; the rest are given once the person exists.
      const assignments = await Promise.allSettled(
        payload.roleIds
          .slice(1)
          .map((roleId) => assignTenantRole(orgSlug, tenantSlug, roleId, invited.id)),
      );
      const rolesRefused = assignments.filter((result) => result.status === 'rejected').length;

      return { created: null, inviteLink: invited.acceptLink, rolesRefused };
    },
    onSuccess: async ({ created, inviteLink, rolesRefused = 0 }, variables) => {
      setIsAddUserModalOpen(false);
      if (rolesRefused > 0) {
        showNotification({
          message: t('toasts.rolesPartlyGiven', { count: rolesRefused }),
          type: 'error',
        });
      }
      if (created) {
        setCreatedUserCredentials({
          email: variables.email,
          password: created.generatedPassword ?? variables.password ?? '',
        });
      }
      if (inviteLink) {
        setInvitationLink({ email: variables.email, link: inviteLink });
      }
      showNotification({
        message: created?.breach?.isBreached
          ? t('toasts.createdBreached', { count: created.breach.occurrences ?? 0 })
          : variables.mode === 'create'
            ? t('toasts.created')
            : t('toasts.invited'),
        type: created?.breach?.isBreached ? 'default' : 'success',
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.addFailed')),
        type: 'error',
      });
    },
  });

  const {
    isPending: isResettingPassword,
    mutate: submitResetPassword,
    reset: resetResetPasswordMutation,
  } = useMutation({
    mutationFn: ({ user, password }: { user: TenantUser; password: string }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return resetTenantUserPassword(orgSlug, tenantSlug, user.id, password);
    },
    onSuccess: async ({ breach, newPassword }, variables) => {
      setResetPasswordUser(null);
      setResetPasswordCredentials({
        email: variables.user.email,
        password: newPassword,
      });
      showNotification({
        message: breach.isBreached
          ? t('toasts.passwordResetBreached', { count: breach.occurrences ?? 0 })
          : t('toasts.passwordReset'),
        type: breach.isBreached ? 'default' : 'success',
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.passwordResetFailed')),
        type: 'error',
      });
    },
  });

  const {
    isPending: isUpdatingRole,
    mutate: submitUpdateRole,
    variables: updateRoleVariables,
  } = useMutation({
    mutationFn: async ({
      addedRoleIds,
      removedRoleIds,
      user,
    }: {
      addedRoleIds: string[];
      removedRoleIds: string[];
      user: TenantUser;
    }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      const results = await Promise.allSettled([
        ...addedRoleIds.map((roleId) => assignTenantRole(orgSlug, tenantSlug, roleId, user.id)),
        ...removedRoleIds.map((roleId) => unassignTenantRole(orgSlug, tenantSlug, roleId, user.id)),
      ]);
      const refused = results.filter((result) => result.status === 'rejected').length;

      const firstRefusal = results.find(
        (result): result is PromiseRejectedResult => result.status === 'rejected',
      );

      if (firstRefusal && refused === results.length) {
        throw firstRefusal.reason;
      }

      return refused;
    },
    onSuccess: async (refused) => {
      showNotification({
        message:
          refused > 0 ? t('toasts.roleUpdatedInPart', { count: refused }) : t('toasts.roleUpdated'),
        type: refused > 0 ? 'error' : 'success',
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.roleUpdateFailed')),
        type: 'error',
      });
    },
  });

  function handleRoleChange(user: TenantUser, roleIds: string[]) {
    if (roleIds.length === 0) {
      showNotification({ message: t('toasts.roleRequired'), type: 'error' });
      return;
    }

    const currentRoleIds = user.roles.map((role) => role.id);
    const addedRoleIds = roleIds.filter((roleId) => !currentRoleIds.includes(roleId));
    const removedRoleIds = currentRoleIds.filter((roleId) => !roleIds.includes(roleId));

    if (addedRoleIds.length === 0 && removedRoleIds.length === 0) {
      return;
    }

    submitUpdateRole({ addedRoleIds, removedRoleIds, user });
  }

  async function handleUserAction(user: TenantUser, action: TenantUserAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    const inviteLink = await executeTenantUserAction(orgSlug, tenantSlug, user, action);

    if (inviteLink) {
      setInvitationLink({ email: user.email, link: inviteLink });
    }

    await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function handleResetPasswordSubmit(data: ResetPasswordInput) {
    if (!resetPasswordUser) {
      return;
    }

    submitResetPassword({ user: resetPasswordUser, password: data.password });
  }

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
            rowsPerPageSelectId="tenant-users-rows-per-page"
            itemCount={usersList?.items.length ?? 0}
            nextCursor={usersList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        secondaryAction={
          canUpdateUser ? (
            <ManageUserFields
              canDelete={canUpdateUser}
              canUpdate={canUpdateUser}
              isOpen={isManageFieldsOpen}
              orgSlug={orgSlug}
              tenantSlug={tenantSlug}
              onOpenChange={setIsManageFieldsOpen}
            />
          ) : undefined
        }
        title={t('title')}
        tabs={
          <DashboardTabs
            activeTab={activeTab}
            tabs={tenantUsersTabs}
            onTabChange={(tab) => {
              setActiveTab(tab);
              resetToFirstPage();
            }}
          />
        }
        onActionClick={
          canCreateUser
            ? () => {
                setCreatedUserCredentials(null);
                resetAddUserMutation();
                setIsAddUserModalOpen(true);
              }
            : undefined
        }
      >
        <TenantUsersTable
          attributeColumns={attributeColumns}
          canAssignRoles={canAssignRoles}
          canDeactivateUser={canDeactivateUser}
          canDeleteUser={canDeleteUser}
          canUpdateUser={canUpdateUser}
          currentUserEmail={currentUserEmail}
          hasFields={attributes.length > 0}
          isLoading={isLoading}
          roleOptions={roleOptions}
          sortDirection={sortDirection}
          sortField={sortField}
          updatingRoleUserId={isUpdatingRole ? (updateRoleVariables?.user.id ?? null) : null}
          users={usersList?.items ?? []}
          onEditFieldsClick={setEditFieldsUser}
          onResetPasswordClick={(user) => {
            setResetPasswordCredentials(null);
            resetResetPasswordMutation();
            setResetPasswordUser(user);
          }}
          onRoleChange={handleRoleChange}
          onSortChange={handleSortChange}
          onUserAction={handleUserAction}
        />
      </DashboardDataCard>

      <EditUserFieldsModal
        canUpdate={canUpdateUser}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        user={editFieldsUser}
        onClose={() => setEditFieldsUser(null)}
        onManageFieldsClick={() => {
          setEditFieldsUser(null);
          setIsManageFieldsOpen(true);
        }}
      />

      <AddTenantUserModal
        isSubmitting={isAddingUser}
        open={isAddUserModalOpen}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => {
          resetAddUserMutation();
          setIsAddUserModalOpen(false);
        }}
        onSubmit={submitAddUser}
      />
      <ResetMemberPasswordModal
        isSubmitting={isResettingPassword}
        member={
          resetPasswordUser
            ? { name: resetPasswordUser.displayName, email: resetPasswordUser.email }
            : null
        }
        onClose={() => {
          resetResetPasswordMutation();
          setResetPasswordUser(null);
        }}
        onSubmit={handleResetPasswordSubmit}
        passwordPolicy={passwordPolicy}
      />
      <MemberCreatedModal
        description={t('invitationLinkDescription')}
        fields={
          invitationLink
            ? [
                { label: t('invitationLinkEmail'), value: invitationLink.email },
                { label: t('invitationLinkLabel'), value: invitationLink.link },
              ]
            : []
        }
        open={Boolean(invitationLink)}
        title={t('invitationLinkTitle')}
        onClose={() => setInvitationLink(null)}
      />
      <MemberCreatedModal
        credentials={createdUserCredentials}
        signInPath={orgSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login'}
        onClose={() => {
          resetAddUserMutation();
          setCreatedUserCredentials(null);
        }}
        title={t('createdTitle')}
      />
      <MemberCreatedModal
        credentials={resetPasswordCredentials}
        description={t('passwordResetDescription')}
        signInPath={orgSlug ? `${getTenantPath(orgSlug, tenantSlug)}/login` : '/login'}
        title={t('passwordResetTitle')}
        onClose={() => {
          resetResetPasswordMutation();
          setResetPasswordCredentials(null);
        }}
      />
    </>
  );
}
