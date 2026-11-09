'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Connection, ConnectionAction, ConnectionStatus } from '@/types/connection';

type ConnectionActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  connection: Connection;
  onActionConfirm: (connection: Connection, action: ConnectionAction) => Promise<void> | void;
  onDeleteClick: (connection: Connection) => void;
};

const connectionActionsByStatus: Record<ConnectionStatus, ConnectionAction[]> = {
  Active: ['Disable'],
  Disabled: ['Activate', 'Delete'],
};

const customConnectionActions: ConnectionAction[] = ['Delete'];

export function ConnectionActionsMenu({
  canDelete = true,
  canUpdate = true,
  connection,
  onActionConfirm,
  onDeleteClick,
}: ConnectionActionsMenuProps) {
  const t = useTranslations('dashboard.connections');
  const tActions = useTranslations('dashboard.actions');
  const tActionLabels = useLooseTranslations('dashboard.actions.labels');
  const connectionActionModalContent = useMemo<
    Partial<Record<ConnectionAction, DashboardActionModalContent>>
  >(
    () => ({
      Activate: {
        title: t('actionModals.activate.title'),
        description: t('actionModals.activate.description'),
        primaryActionLabel: t('actionModals.activate.submit'),
      },
      Disable: {
        title: t('actionModals.disable.title'),
        description: t('actionModals.disable.description'),
        primaryActionLabel: t('actionModals.disable.submit'),
      },
    }),
    [t],
  );
  const availableActions = connectionActionsByStatus[connection.status].filter((action) =>
    action === 'Delete' ? canDelete : canUpdate,
  );
  const availableCustomActions = customConnectionActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: connection.name })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) => tActions('completed', { action: tActionLabels(action) })}
      modalContentByAction={connectionActionModalContent}
      onActionConfirm={(action) => onActionConfirm(connection, action)}
      onCustomAction={(action) => {
        if (action === 'Delete') {
          onDeleteClick(connection);
        }
      }}
    />
  );
}
