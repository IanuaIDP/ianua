'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import type { Group, GroupAction } from '@/types/group';

const groupActions: GroupAction[] = ['Edit', 'Members', 'Roles', 'Delete'];

type GroupActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  group: Group;
  onDeleteClick: (group: Group) => void;
  onEditClick: (group: Group) => void;
  onMembersClick: (group: Group) => void;
  onRolesClick: (group: Group) => void;
};

export function GroupActionsMenu({
  canDelete = true,
  canUpdate = true,
  group,
  onDeleteClick,
  onEditClick,
  onMembersClick,
  onRolesClick,
}: GroupActionsMenuProps) {
  const tActions = useTranslations('dashboard.actions');
  const availableActions = groupActions.filter((action) =>
    action === 'Delete' ? canDelete : canUpdate,
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: group.name })}
      customActions={availableActions}
      modalContentByAction={{}}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(group);
          return;
        }

        if (action === 'Members') {
          onMembersClick(group);
          return;
        }

        if (action === 'Roles') {
          onRolesClick(group);
          return;
        }

        if (action === 'Delete') {
          onDeleteClick(group);
        }
      }}
    />
  );
}
