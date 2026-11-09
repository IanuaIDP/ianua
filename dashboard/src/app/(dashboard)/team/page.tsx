'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isAxiosError } from 'axios';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardPageContent } from '@/components/dashboard/shared/dashboard-page-content';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { ResetMemberPasswordModal } from '@/components/dashboard/shared/reset-member-password-modal';
import { AddTeamMemberModal } from '@/components/dashboard/team/add-team-member-modal';
import { MemberTenantAccessModal } from '@/components/dashboard/team/member-tenant-access-modal';
import { TeamCard } from '@/components/dashboard/team/team-card';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useOrgPasswordPolicy } from '@/hooks/auth/use-password-policy';
import type { ResetPasswordInput } from '@/schemas/reset-password-schema';
import type { AddTeamMemberInput } from '@/schemas/team-member-schemas';
import type { OrgRole } from '@/types/auth';
import type { CreatedMemberCredentials } from '@/types/member';
import type {
  TeamMember,
  TeamMemberAction,
  TeamMemberSortField,
  TeamMemberTab,
} from '@/types/team';
import { useAuthStore } from '@/store/auth-store';
import {
  changeTeamMemberRole,
  createTeamMember,
  deriveErrorMessage,
  executeTeamMemberAction,
  getApiErrorMessage,
  getTeamMembers,
  inviteTeamMember,
  resetTeamMemberPassword,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';

const teamMembersTabs: TeamMemberTab[] = [
  'All',
  'Active',
  'Locked',
  'Invited',
  'PendingVerification',
  'InvitationExpired',
];

export default function TeamPage() {
  const t = useTranslations('dashboard.team');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const currentUserEmail = useAuthStore((state) => state.user?.email);
  const { canManageOrganization } = useOrgAccess();
  const passwordPolicy = useOrgPasswordPolicy(organizationSlug);
  const [activeTab, setActiveTab] = useState<TeamMemberTab>('All');
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
  } = useTableQueryState<TeamMemberSortField>();
  const [createdMemberCredentials, setCreatedMemberCredentials] =
    useState<CreatedMemberCredentials | null>(null);
  const [isAddTeamMemberModalOpen, setIsAddTeamMemberModalOpen] = useState(false);
  const [resetPasswordMember, setResetPasswordMember] = useState<TeamMember | null>(null);
  const [tenantAccessMember, setTenantAccessMember] = useState<TeamMember | null>(null);
  const [invitationLink, setInvitationLink] = useState<{ email: string; link: string } | null>(
    null,
  );
  const [resetPasswordCredentials, setResetPasswordCredentials] =
    useState<CreatedMemberCredentials | null>(null);
  const [pendingRoleChange, setPendingRoleChange] = useState<{
    member: TeamMember;
    role: OrgRole;
  } | null>(null);
  const status = activeTab === 'All' ? undefined : activeTab;

  const {
    data: teamMembersList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () =>
      getTeamMembers(organizationSlug ?? '', {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
        status,
      }),
    queryKey: ['team', organizationSlug, status, sortField, sortDirection, after, rowsPerPage],
  });

  const { data: orgMemberCount } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getTeamMembers(organizationSlug ?? '', { limit: 2 }),
    queryKey: ['team-total', organizationSlug],
    select: (data) => data.items.length,
  });
  const {
    isPending: isAddingTeamMember,
    mutate: submitAddTeamMember,
    reset: resetAddTeamMemberMutation,
  } = useMutation({
    mutationFn: async (payload: AddTeamMemberInput) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (payload.mode === 'create') {
        await createTeamMember(organizationSlug, payload);

        return null;
      }

      return inviteTeamMember(organizationSlug, payload);
    },
    onSuccess: async (inviteLink, variables) => {
      setIsAddTeamMemberModalOpen(false);
      if (variables.mode === 'create') {
        setCreatedMemberCredentials({
          email: variables.email,
          password: variables.password ?? '',
        });
      }
      if (inviteLink) {
        setInvitationLink({ email: variables.email, link: inviteLink });
      }
      showNotification({
        message: variables.mode === 'create' ? t('toasts.created') : t('toasts.invited'),
        type: 'success',
      });
      resetToFirstPage();
      await queryClient.invalidateQueries({ queryKey: ['team', organizationSlug] });
      await queryClient.invalidateQueries({ queryKey: ['team-total', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
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
    mutationFn: ({ member, password }: { member: TeamMember; password: string }) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return resetTeamMemberPassword(organizationSlug, member.id, password);
    },
    onSuccess: async (_data, variables) => {
      setResetPasswordMember(null);
      setResetPasswordCredentials({
        email: variables.member.email,
        password: variables.password,
      });
      showNotification({ message: t('toasts.passwordReset'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.passwordResetFailed')),
        type: 'error',
      });
    },
  });

  const {
    isPending: isChangingRole,
    mutate: submitRoleChange,
    variables: roleChangeVariables,
  } = useMutation({
    mutationFn: ({ member, role }: { member: TeamMember; role: OrgRole }) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return changeTeamMemberRole(organizationSlug, member.id, role);
    },
    onSuccess: async (_data, variables) => {
      setPendingRoleChange(null);
      showNotification({
        message: t('toasts.roleChanged', {
          name: variables.member.name,
          role: variables.role,
        }),
        type: 'success',
      });
      await queryClient.invalidateQueries({ queryKey: ['team', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      const status = isAxiosError(error) ? error.response?.status : undefined;
      const fallbackMessage =
        status === 409
          ? t('toasts.lastOwner')
          : status === 422
            ? t('cannotChangeOwnRole')
            : t('toasts.roleChangeFailed');

      showNotification({
        message: getApiErrorMessage(error, fallbackMessage),
        type: 'error',
      });
    },
  });

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const handleMemberAction = async (member: TeamMember, action: TeamMemberAction) => {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    const inviteLink = await executeTeamMemberAction(organizationSlug, member, action);

    if (inviteLink) {
      setInvitationLink({ email: member.email, link: inviteLink });
    }

    await queryClient.invalidateQueries({ queryKey: ['team', organizationSlug] });
    await queryClient.invalidateQueries({ queryKey: ['team-total', organizationSlug] });
    await invalidateAuditLogQueries(queryClient, organizationSlug);
  };

  const handleResetPasswordSubmit = (data: ResetPasswordInput) => {
    if (!resetPasswordMember) {
      return;
    }

    submitResetPassword({ member: resetPasswordMember, password: data.password });
  };

  return (
    <div>
      <DashboardPageHeader icon="groups" title={t('title')} />
      <DashboardPageContent>
        <TeamCard
          canManageMembers={canManageOrganization}
          changingRoleMemberId={isChangingRole ? (roleChangeVariables?.member.id ?? null) : null}
          currentPage={currentPage}
          currentUserEmail={currentUserEmail}
          members={teamMembersList?.items ?? []}
          orgMemberCount={orgMemberCount ?? 0}
          nextCursor={teamMembersList?.nextCursor ?? null}
          rowsPerPage={rowsPerPage}
          onAddMemberClick={() => {
            setCreatedMemberCredentials(null);
            resetAddTeamMemberMutation();
            setIsAddTeamMemberModalOpen(true);
          }}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onMemberAction={handleMemberAction}
          onResetPasswordClick={(member) => {
            setResetPasswordCredentials(null);
            resetResetPasswordMutation();
            setResetPasswordMember(member);
          }}
          onRoleChange={(member, role) => setPendingRoleChange({ member, role })}
          onTenantAccessClick={setTenantAccessMember}
          onRowsPerPageChange={handleRowsPerPageChange}
          activeTab={activeTab}
          tabs={teamMembersTabs}
          onTabChange={(tab) => {
            setActiveTab(tab);
            resetToFirstPage();
          }}
          errorMessage={errorMessage}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onSortChange={handleSortChange}
        />
      </DashboardPageContent>

      <AddTeamMemberModal
        isSubmitting={isAddingTeamMember}
        open={isAddTeamMemberModalOpen}
        orgSlug={organizationSlug}
        onClose={() => {
          resetAddTeamMemberMutation();
          setIsAddTeamMemberModalOpen(false);
        }}
        onSubmit={submitAddTeamMember}
      />
      <MemberCreatedModal
        credentials={createdMemberCredentials}
        onClose={() => {
          resetAddTeamMemberMutation();
          setCreatedMemberCredentials(null);
        }}
      />
      {organizationSlug ? (
        <MemberTenantAccessModal
          member={tenantAccessMember}
          orgSlug={organizationSlug}
          onClose={() => setTenantAccessMember(null)}
        />
      ) : null}
      <ResetMemberPasswordModal
        isSubmitting={isResettingPassword}
        member={resetPasswordMember}
        onClose={() => {
          resetResetPasswordMutation();
          setResetPasswordMember(null);
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
        credentials={resetPasswordCredentials}
        description={t('passwordResetDescription')}
        title={t('passwordResetTitle')}
        onClose={() => {
          resetResetPasswordMutation();
          setResetPasswordCredentials(null);
        }}
      />
      <Modal
        open={Boolean(pendingRoleChange)}
        onClose={() => {
          if (!isChangingRole) {
            setPendingRoleChange(null);
          }
        }}
        title={t('roleChange.title')}
        description={
          pendingRoleChange
            ? t('roleChange.description', {
                name: pendingRoleChange.member.name,
                role: pendingRoleChange.role,
              })
            : undefined
        }
        primaryActionLabel={t('roleChange.submit')}
        onPrimaryAction={() => {
          if (pendingRoleChange) {
            submitRoleChange(pendingRoleChange);
          }
        }}
        isPrimaryActionLoading={isChangingRole}
        isPrimaryActionDisabled={isChangingRole}
        showCloseButton={false}
      >
        <p className="text-xs text-textGray">
          {pendingRoleChange ? t(`roleChange.consequences.${pendingRoleChange.role}`) : null}
        </p>
      </Modal>
    </div>
  );
}
