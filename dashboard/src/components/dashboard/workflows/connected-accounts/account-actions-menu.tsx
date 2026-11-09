'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { WorkflowAccount } from '@/types/workflows';

export type AccountAction =
  'Rename' | 'Replace' | 'Limit' | 'Events' | 'Share' | 'Keep' | 'Disable' | 'Enable';

type AccountActionsMenuProps = {
  account: WorkflowAccount;
  canManage: boolean;
  isOwner: boolean;
  onAction: (action: AccountAction) => void;
  onConfirm: (action: AccountAction) => Promise<void>;
};

const OWNER_ACTIONS: AccountAction[] = ['Replace', 'Limit', 'Events'];

function actionsFor(account: WorkflowAccount, isOwner: boolean, canManage: boolean) {
  const actions: AccountAction[] = [];

  if (isOwner || canManage) {
    actions.push('Rename', account.status === 'disabled' ? 'Enable' : 'Disable');
  }

  if (isOwner) {
    actions.push(...OWNER_ACTIONS, account.sharing === 'tenant' ? 'Keep' : 'Share');
  }

  return actions;
}

/** What a person may do to one account: widening it is the owner's alone. */
export function AccountActionsMenu({
  account,
  canManage,
  isOwner,
  onAction,
  onConfirm,
}: AccountActionsMenuProps) {
  const t = useTranslations('dashboard.connectedAccounts.actions');
  const actions = actionsFor(account, isOwner, canManage);

  return (
    <DashboardActionsMenu
      actionLabels={{
        Disable: t('disable'),
        Enable: t('enable'),
        Events: t('events'),
        Keep: t('keep'),
        Limit: t('limit'),
        Rename: t('rename'),
        Replace: t('replace'),
        Share: t('share'),
      }}
      actions={actions}
      ariaLabel={t('menu', { name: account.name })}
      customActions={['Rename', 'Replace', 'Limit', 'Events']}
      instantActions={['Enable', 'Share', 'Keep']}
      modalContentByAction={{
        Disable: {
          description: t('disableDescription', { name: account.name }),
          primaryActionLabel: t('disable'),
          secondaryActionLabel: t('dismiss'),
          title: t('disableTitle', { name: account.name }),
          warningNote: t('disableWarning'),
        },
      }}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('failed'))}
      onActionConfirm={onConfirm}
      onCustomAction={onAction}
    />
  );
}
