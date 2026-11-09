'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { OpenStreamRouteModal } from '@/components/dashboard/tenant-detail/sections/routes/open-stream-route-modal';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { StreamRoute, StreamRouteAction, StreamRouteStatus } from '@/types/stream-route';

const actionsByStatus: Record<StreamRouteStatus, StreamRouteAction[]> = {
  Active: ['Edit', 'Disable'],
  Disabled: ['Enable', 'Delete'],
};

const customActions: StreamRouteAction[] = ['Edit', 'OpenToWorkflows'];
const updateActions: StreamRouteAction[] = [
  'Edit',
  'Enable',
  'Disable',
  'OpenToWorkflows',
  'CloseToWorkflows',
];

type StreamRouteActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  onActionConfirm: (route: StreamRoute, action: StreamRouteAction) => Promise<void> | void;
  onEditClick: (route: StreamRoute) => void;
  route: StreamRoute;
};

export function StreamRouteActionsMenu({
  canDelete = true,
  canUpdate = true,
  onActionConfirm,
  onEditClick,
  route,
}: StreamRouteActionsMenuProps) {
  const t = useTranslations('dashboard.ports');
  const tActions = useTranslations('dashboard.actions');
  const [isOpeningToWorkflows, setIsOpeningToWorkflows] = useState(false);
  const modalContent: Partial<Record<StreamRouteAction, DashboardActionModalContent>> = {
    Enable: {
      title: t('actionModals.Enable.title'),
      description: t('actionModals.Enable.description'),
      primaryActionLabel: t('actionModals.Enable.submit'),
    },
    Disable: {
      title: t('actionModals.Disable.title'),
      description: t('actionModals.Disable.description'),
      primaryActionLabel: t('actionModals.Disable.submit'),
      confirmationPlaceholder: 'DISABLE',
      confirmationValue: 'DISABLE',
    },
    CloseToWorkflows: {
      title: t('actionModals.CloseToWorkflows.title'),
      description: t('actionModals.CloseToWorkflows.description'),
      primaryActionLabel: t('actionModals.CloseToWorkflows.submit'),
    },
    Delete: {
      title: t('actionModals.Delete.title'),
      description: t('actionModals.Delete.description'),
      primaryActionLabel: t('actionModals.Delete.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
    },
  };
  const workflowAction: StreamRouteAction =
    route.workflowUse === 'open' ? 'CloseToWorkflows' : 'OpenToWorkflows';
  const availableActions = [...actionsByStatus[route.status], workflowAction].filter((action) => {
    if (action === 'Delete') {
      return canDelete;
    }

    if (updateActions.includes(action)) {
      return canUpdate;
    }

    return true;
  });
  const availableCustomActions = customActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <>
      <DashboardActionsMenu
        actionLabels={{
          CloseToWorkflows: t('actionModals.CloseToWorkflows.label'),
          OpenToWorkflows: t('actionModals.OpenToWorkflows.label'),
        }}
        actions={availableActions}
        ariaLabel={tActions('openActionsFor', { name: route.name })}
        customActions={availableCustomActions}
        getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
        getActionSuccessMessage={(action) =>
          action === 'Edit' ? tActions('succeeded') : t(`actionSuccess.${action}`)
        }
        modalContentByAction={modalContent}
        onActionConfirm={(action) => onActionConfirm(route, action)}
        onCustomAction={(action) => {
          if (action === 'Edit') {
            onEditClick(route);
          }

          if (action === 'OpenToWorkflows') {
            setIsOpeningToWorkflows(true);
          }
        }}
      />
      <OpenStreamRouteModal
        onClose={() => setIsOpeningToWorkflows(false)}
        open={isOpeningToWorkflows}
        route={route}
      />
    </>
  );
}
