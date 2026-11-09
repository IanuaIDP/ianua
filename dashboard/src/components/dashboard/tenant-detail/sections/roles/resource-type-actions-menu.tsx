'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import type { ResourceType, ResourceTypeAction } from '@/types/resource-type';

const resourceTypeActions: ResourceTypeAction[] = ['Edit', 'Delete'];

type ResourceTypeActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  onDeleteClick: (resourceType: ResourceType) => void;
  onEditClick: (resourceType: ResourceType) => void;
  resourceType: ResourceType;
};

export function ResourceTypeActionsMenu({
  canDelete = true,
  canUpdate = true,
  onDeleteClick,
  onEditClick,
  resourceType,
}: ResourceTypeActionsMenuProps) {
  const tActions = useTranslations('dashboard.actions');
  const availableActions = resourceTypeActions.filter((action) =>
    action === 'Delete' ? canDelete : canUpdate,
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: resourceType.displayName })}
      customActions={availableActions}
      modalContentByAction={{}}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(resourceType);
          return;
        }

        if (action === 'Delete') {
          onDeleteClick(resourceType);
        }
      }}
    />
  );
}
