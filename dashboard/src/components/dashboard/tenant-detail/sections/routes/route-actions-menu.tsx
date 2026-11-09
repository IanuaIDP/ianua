'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Route, RouteAction, RouteStatus } from '@/types/route';

const routeActionsByStatus: Record<RouteStatus, RouteAction[]> = {
  Active: ['Edit', 'Disable'],
  Disabled: ['Enable', 'Delete'],
};

const customRouteActions: RouteAction[] = ['Edit'];

type RouteActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  onActionConfirm: (route: Route, action: RouteAction) => Promise<void> | void;
  onEditClick: (route: Route) => void;
  route: Route;
};

const updateRouteActions: RouteAction[] = [
  'Edit',
  'Enable',
  'Disable',
  'OpenToWorkflows',
  'CloseToWorkflows',
];

export function RouteActionsMenu({
  canDelete = true,
  canUpdate = true,
  onActionConfirm,
  onEditClick,
  route,
}: RouteActionsMenuProps) {
  const t = useTranslations('dashboard.routes');
  const tActions = useTranslations('dashboard.actions');
  const routeActionModalContent: Partial<Record<RouteAction, DashboardActionModalContent>> = {
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
    OpenToWorkflows: {
      title: t('actionModals.OpenToWorkflows.title'),
      description: t('actionModals.OpenToWorkflows.description'),
      primaryActionLabel: t('actionModals.OpenToWorkflows.submit'),
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
  const workflowAction: RouteAction =
    route.workflowUse === 'open' ? 'CloseToWorkflows' : 'OpenToWorkflows';
  const availableActions = [...routeActionsByStatus[route.status], workflowAction].filter(
    (action) => {
      if (action === 'Delete') {
        return canDelete;
      }

      if (updateRouteActions.includes(action)) {
        return canUpdate;
      }

      return true;
    },
  );
  const availableCustomActions = customRouteActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
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
      modalContentByAction={routeActionModalContent}
      onActionConfirm={(action) => onActionConfirm(route, action)}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(route);
        }
      }}
    />
  );
}
