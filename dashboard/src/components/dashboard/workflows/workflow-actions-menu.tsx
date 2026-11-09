'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';

export type WorkflowAction = 'Open' | 'Runs' | 'Start';

type WorkflowMenuAction = WorkflowAction | 'Remove';

type WorkflowActionsMenuProps = {
  canRemove: boolean;
  canStart: boolean;
  onAction: (action: WorkflowAction) => void;
  onRemove: () => Promise<void>;
  workflowName: string;
};

/** A row's menu in the workflow list. */
export function WorkflowActionsMenu({
  canRemove,
  canStart,
  onAction,
  onRemove,
  workflowName,
}: WorkflowActionsMenuProps) {
  const t = useTranslations('dashboard.workflows.actions');
  const customActions: WorkflowAction[] = [
    'Open',
    'Runs',
    ...(canStart ? (['Start'] as const) : []),
  ];
  const actions: WorkflowMenuAction[] = [
    ...customActions,
    ...(canRemove ? (['Remove'] as const) : []),
  ];

  return (
    <DashboardActionsMenu<WorkflowMenuAction>
      actionLabels={{ Open: t('open'), Remove: t('remove'), Runs: t('runs'), Start: t('start') }}
      actions={actions}
      ariaLabel={t('menu', { name: workflowName })}
      customActions={customActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('removeFailed'))}
      getActionSuccessMessage={() => t('removed')}
      modalContentByAction={{
        Remove: {
          title: t('removeTitle', { name: workflowName }),
          description: t('removeDescription'),
          primaryActionLabel: t('remove'),
          warningTone: 'danger',
        },
      }}
      onActionConfirm={onRemove}
      onCustomAction={(action) => onAction(action as WorkflowAction)}
    />
  );
}
