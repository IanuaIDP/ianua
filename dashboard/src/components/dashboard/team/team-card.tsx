'use client';

import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { TeamTable } from '@/components/dashboard/team/team-table';
import type { OrgRole } from '@/types/auth';
import type {
  TeamMember,
  TeamMemberAction,
  TeamMemberSortDirection,
  TeamMemberSortField,
  TeamMemberTab,
} from '@/types/team';
import { DashboardTabs } from '../shared/dashboard-tabs';

type TeamCardProps = {
  activeTab: TeamMemberTab;
  canManageMembers?: boolean;
  changingRoleMemberId?: number | string | null;
  currentPage: number;
  currentUserEmail?: string;
  isLoading?: boolean;
  members: TeamMember[];
  onAddMemberClick: () => void;
  onMemberAction: (member: TeamMember, action: TeamMemberAction) => Promise<void> | void;
  nextCursor: string | null;
  onNext: (nextCursor: string) => void;
  onPrevious: () => void;
  onResetPasswordClick: (member: TeamMember) => void;
  onRoleChange: (member: TeamMember, role: OrgRole) => void;
  onTenantAccessClick: (member: TeamMember) => void;
  onRowsPerPageChange: (rowsPerPage: number) => void;
  onSortChange: (field: TeamMemberSortField) => void;
  orgMemberCount?: number;
  rowsPerPage: number;
  tabs: TeamMemberTab[];
  onTabChange: (tab: TeamMemberTab) => void;
  errorMessage?: string;
  sortDirection?: TeamMemberSortDirection;
  sortField?: TeamMemberSortField;
};

export function TeamCard({
  activeTab,
  canManageMembers = false,
  changingRoleMemberId = null,
  currentPage,
  currentUserEmail,
  isLoading = false,
  members,
  onAddMemberClick,
  onMemberAction,
  nextCursor,
  onNext,
  onPrevious,
  onResetPasswordClick,
  onRoleChange,
  onTenantAccessClick,
  onRowsPerPageChange,
  onSortChange,
  orgMemberCount = 0,
  rowsPerPage,
  tabs,
  onTabChange,
  errorMessage,
  sortDirection,
  sortField,
}: TeamCardProps) {
  const t = useTranslations('dashboard.team');
  const isOnlyMember = orgMemberCount === 1;

  return (
    <DashboardDataCard
      actionLabel={canManageMembers ? t('addMember') : undefined}
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="team-rows-per-page"
          itemCount={members.length}
          nextCursor={nextCursor}
          onNext={onNext}
          onPrevious={onPrevious}
          onRowsPerPageChange={onRowsPerPageChange}
        />
      }
      title={t('title')}
      onActionClick={canManageMembers ? onAddMemberClick : undefined}
      tabs={<DashboardTabs activeTab={activeTab} tabs={tabs} onTabChange={onTabChange} />}
    >
      <TeamTable
        canManageMembers={canManageMembers}
        changingRoleMemberId={changingRoleMemberId}
        currentUserEmail={currentUserEmail}
        isLoading={isLoading}
        isOnlyMember={isOnlyMember}
        members={members}
        sortDirection={sortDirection}
        sortField={sortField}
        onMemberAction={onMemberAction}
        onResetPasswordClick={onResetPasswordClick}
        onRoleChange={onRoleChange}
        onTenantAccessClick={onTenantAccessClick}
        onSortChange={onSortChange}
      />
    </DashboardDataCard>
  );
}
