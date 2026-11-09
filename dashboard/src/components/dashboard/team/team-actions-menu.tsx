'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { createMemberActionModalContent } from '@/components/dashboard/shared/member-action-modal-content';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage } from '@/lib/api';
import { DashboardActionModalContent } from '@/types/dashboard';
import type { TeamMember, TeamMemberAction, TeamMemberStatus } from '@/types/team';

type TeamActionsMenuProps = {
  canActOnMember?: boolean;
  isOnlyMember?: boolean;
  isSelf?: boolean;
  member: TeamMember;
  onActionConfirm: (member: TeamMember, action: TeamMemberAction) => Promise<void> | void;
  onResetPasswordClick: (member: TeamMember) => void;
  onTenantAccessClick: (member: TeamMember) => void;
};

const teamActionsByStatus: Record<TeamMemberStatus, TeamMemberAction[]> = {
  Active: ['Tenant Access', 'Lock', 'Reset Password', 'Reset Second Factor', 'Delete Forever'],
  Locked: ['Restore Access'],
  Invited: ['Tenant Access', 'Revoke Invitation'],
  PendingVerification: ['Tenant Access', 'Delete Forever'],
  InvitationExpired: ['Resend Invitation', 'Delete Forever'],
};

const instantTeamActions: TeamMemberAction[] = ['Resend Invitation'];
const customTeamActions: TeamMemberAction[] = ['Reset Password', 'Tenant Access'];

export function TeamActionsMenu({
  canActOnMember = true,
  isOnlyMember = false,
  isSelf = false,
  member,
  onActionConfirm,
  onResetPasswordClick,
  onTenantAccessClick,
}: TeamActionsMenuProps) {
  const t = useTranslations('dashboard.actions');
  const tMember = useLooseTranslations('dashboard.memberActions');
  const tActionLabels = useLooseTranslations('dashboard.actions.labels');
  const teamActionModalContent = useMemo<
    Partial<Record<TeamMemberAction, DashboardActionModalContent>>
  >(
    () => ({
      ...createMemberActionModalContent(tMember, 'teamMember'),
      'Reset Second Factor': {
        title: tMember('teamMember.resetSecondFactor.title'),
        description: tMember('teamMember.resetSecondFactor.description'),
        primaryActionLabel: tMember('teamMember.resetSecondFactor.primary'),
      },
    }),
    [tMember],
  );
  const forStatus = teamActionsByStatus[member.status].filter(
    (action) => action !== 'Tenant Access' || member.role === 'Member',
  );
  const allowedActions = canActOnMember ? forStatus : [];
  const availableActions =
    isOnlyMember || isSelf
      ? allowedActions.filter((action) => action === 'Reset Password')
      : allowedActions;

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={t('openActionsFor', { name: member.name })}
      customActions={customTeamActions}
      getActionErrorMessage={(error) =>
        getApiErrorMessage(error, tMember('teamMember.updateFailed'))
      }
      getActionSuccessMessage={(action) => t('completed', { action: tActionLabels(action) })}
      instantActions={instantTeamActions}
      modalContentByAction={teamActionModalContent}
      onActionConfirm={(action) => onActionConfirm(member, action)}
      onCustomAction={(action) => {
        if (action === 'Reset Password') {
          onResetPasswordClick(member);
        }
        if (action === 'Tenant Access') {
          onTenantAccessClick(member);
        }
      }}
    />
  );
}
