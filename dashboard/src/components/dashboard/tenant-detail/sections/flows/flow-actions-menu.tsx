'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useFlowText } from '@/hooks/dashboard/use-flow-text';
import { getApiErrorMessage } from '@/lib/api';
import type { Flow, FlowAction } from '@/types/flow';

type FlowActionsMenuProps = {
  canCancel: boolean;
  canDelete: boolean;
  flow: Flow;
  onActionConfirm: (flow: Flow, action: FlowAction) => Promise<void> | void;
};

export function FlowActionsMenu({
  canCancel,
  canDelete,
  flow,
  onActionConfirm,
}: FlowActionsMenuProps) {
  const t = useTranslations('dashboard.flows');
  const tActions = useTranslations('dashboard.actions');
  const { actionModalContent } = useFlowText();
  const actions: FlowAction[] = [
    ...(canCancel && flow.status === 'Running' ? (['Cancel'] as const) : []),
    ...(canDelete ? (['Delete'] as const) : []),
  ];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: flow.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        action === 'Cancel' ? t('toasts.cancelled') : t('toasts.deleted')
      }
      modalContentByAction={actionModalContent(flow)}
      onActionConfirm={(action) => onActionConfirm(flow, action)}
    />
  );
}
