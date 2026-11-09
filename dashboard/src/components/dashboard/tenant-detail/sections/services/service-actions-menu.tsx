'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { GatewayService, GatewayServiceAction } from '@/types/gateway-service';

const customServiceActions: GatewayServiceAction[] = ['Edit'];

type ServiceActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  onActionConfirm: (service: GatewayService, action: GatewayServiceAction) => Promise<void> | void;
  onEditClick: (service: GatewayService) => void;
  service: GatewayService;
};

export function ServiceActionsMenu({
  canDelete = true,
  canUpdate = true,
  onActionConfirm,
  onEditClick,
  service,
}: ServiceActionsMenuProps) {
  const t = useTranslations('dashboard.services');
  const tActions = useTranslations('dashboard.actions');
  const serviceActionModalContent: Partial<
    Record<GatewayServiceAction, DashboardActionModalContent>
  > = {
    Delete: {
      title: t('deleteModal.title'),
      description: t('deleteModal.description'),
      primaryActionLabel: t('deleteModal.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
    },
  };
  const availableActions = (['Edit', 'Delete'] as GatewayServiceAction[]).filter((action) =>
    action === 'Delete' ? canDelete : canUpdate,
  );
  const availableCustomActions = customServiceActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: service.name })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        action === 'Delete' ? t('toasts.deleted') : tActions('succeeded')
      }
      modalContentByAction={serviceActionModalContent}
      onActionConfirm={(action) => onActionConfirm(service, action)}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(service);
        }
      }}
    />
  );
}
