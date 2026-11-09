'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TeamActionsMenu } from '@/components/dashboard/team/team-actions-menu';
import { Select } from '@/components/ui/Select';
import { TableCellStack, TableCellText } from '@/components/ui/table-cell';
import { Tooltip } from '@/components/ui/tooltip';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import type { OrgRole } from '@/types/auth';
import type {
  TeamMember,
  TeamMemberAction,
  TeamMemberSortDirection,
  TeamMemberSortField,
} from '@/types/team';
import { getBadgeColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { DashboardStatusBadge } from '../shared/dashboard-status-badge';

type TeamTableProps = {
  canManageMembers?: boolean;
  changingRoleMemberId?: number | string | null;
  currentUserEmail?: string;
  isLoading?: boolean;
  isOnlyMember?: boolean;
  members: TeamMember[];
  onMemberAction: (member: TeamMember, action: TeamMemberAction) => Promise<void> | void;
  onResetPasswordClick: (member: TeamMember) => void;
  onRoleChange: (member: TeamMember, role: OrgRole) => void;
  onSortChange: (field: TeamMemberSortField) => void;
  onTenantAccessClick: (member: TeamMember) => void;
  sortDirection?: TeamMemberSortDirection;
  sortField?: TeamMemberSortField;
};

export function TeamTable({
  canManageMembers = false,
  changingRoleMemberId = null,
  currentUserEmail,
  isLoading = false,
  isOnlyMember = false,
  members,
  onMemberAction,
  onResetPasswordClick,
  onRoleChange,
  onSortChange,
  onTenantAccessClick,
  sortDirection,
  sortField,
}: TeamTableProps) {
  const t = useTranslations('dashboard.team');
  const tRoles = useTranslations('dashboard.roles');
  const columns = useMemo<DashboardTableColumn<TeamMemberSortField>[]>(
    () => [
      { className: 'w-[40%]', label: t('columns.name'), sortField: 'display_name' },
      { className: 'w-[16%]', label: t('columns.role') },
      { className: 'w-[22%]', label: t('columns.status') },
      { className: 'w-[22%]', label: t('columns.joined'), sortField: 'created_at' },
    ],
    [t],
  );
  const { assignableRoles } = useOrgAccess();
  const roleOptions = assignableRoles.map((role) => ({ label: tRoles(role), value: role }));

  return (
    <DashboardTableShell
      className="mt-4"
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn={canManageMembers}
      isEmpty={members.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {members.map((member) => {
        const isSelf =
          Boolean(currentUserEmail) &&
          Boolean(member.email) &&
          member.email.toLowerCase() === currentUserEmail?.toLowerCase();
        const canActOnMember = assignableRoles.includes(member.role);

        return (
          <tr key={member.id} className="group h-11 transition hover:bg-hoverBg">
            <td className="px-4 py-2">
              <div className="flex min-w-0 items-center gap-3">
                <span
                  className={cn(
                    'flex size-6 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                    getBadgeColorClass(member.id),
                  )}
                >
                  {member.avatarInitial}
                </span>
                <TableCellStack
                  primary={isSelf ? t('me', { name: member.name }) : member.name}
                  primaryClassName="font-semibold text-white"
                  secondary={member.email}
                  secondaryClassName="text-[10px] font-medium text-textGray"
                />
              </div>
            </td>
            <td className="px-4 py-2">
              {!canManageMembers || !canActOnMember ? (
                <TableCellText>{tRoles(member.role)}</TableCellText>
              ) : (
                <Tooltip
                  content={t('cannotChangeOwnRole')}
                  disabled={!isSelf}
                  side="top"
                  className="block"
                >
                  <Select
                    containerClassName="mb-0"
                    className="h-8 text-xs"
                    disabled={
                      isOnlyMember ||
                      isSelf ||
                      changingRoleMemberId === member.id ||
                      member.status !== 'Active'
                    }
                    options={roleOptions}
                    value={member.role}
                    onChange={(value) => onRoleChange(member, value as OrgRole)}
                  />
                </Tooltip>
              )}
            </td>
            <td className="px-4 py-2">
              <DashboardStatusBadge status={member.status} />
            </td>
            <td className="px-4 py-2">
              <TableCellText>{member.joined}</TableCellText>
            </td>
            {canManageMembers ? (
              <DashboardTableActionsCell>
                <TeamActionsMenu
                  canActOnMember={canActOnMember}
                  isOnlyMember={isOnlyMember}
                  isSelf={isSelf}
                  member={member}
                  onActionConfirm={onMemberAction}
                  onResetPasswordClick={onResetPasswordClick}
                  onTenantAccessClick={onTenantAccessClick}
                />
              </DashboardTableActionsCell>
            ) : null}
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
