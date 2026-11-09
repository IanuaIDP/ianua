'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import type { Role, RoleAction } from '@/types/role';

const roleActions: RoleAction[] = ['Edit', 'Delete'];
const customRoleActions: RoleAction[] = ['Edit', 'Delete'];

type RoleActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  onDeleteClick: (role: Role) => void;
  onEditClick: (role: Role) => void;
  role: Role;
};

export function RoleActionsMenu({
  canDelete = true,
  canUpdate = true,
  onDeleteClick,
  onEditClick,
  role,
}: RoleActionsMenuProps) {
  const tActions = useTranslations('dashboard.actions');
  const availableActions = role.isDefault
    ? []
    : roleActions.filter((action) => (action === 'Delete' ? canDelete : canUpdate));
  const availableCustomActions = customRoleActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: role.name })}
      customActions={availableCustomActions}
      modalContentByAction={{}}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(role);
          return;
        }

        if (action === 'Delete') {
          onDeleteClick(role);
        }
      }}
    />
  );
}
