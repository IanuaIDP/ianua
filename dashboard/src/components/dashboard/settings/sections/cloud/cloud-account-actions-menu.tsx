'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getCloudProviderLabel } from '@/constants/cloud';
import { getApiErrorMessage } from '@/lib/api';
import type { CloudAccount, CloudAccountAction } from '@/types/cloud-account';
import type { DashboardActionModalContent } from '@/types/dashboard';

type CloudAccountActionsMenuProps = {
  account: CloudAccount;
  onActionConfirm: (account: CloudAccount, action: CloudAccountAction) => Promise<void> | void;
};

export function CloudAccountActionsMenu({
  account,
  onActionConfirm,
}: CloudAccountActionsMenuProps) {
  const t = useTranslations('dashboard.settings.cloud');
  const tActions = useTranslations('dashboard.actions');
  const cloudAccountActionModalContent: Record<CloudAccountAction, DashboardActionModalContent> = {
    Disconnect: {
      title: t('actions.disconnect.title'),
      description: t('actions.disconnect.description'),
      primaryActionLabel: t('actions.disconnect.submit'),
    },
    Reverify: {
      title: t('actions.reverify.title'),
      description: t('actions.reverify.description'),
      primaryActionLabel: t('actions.reverify.submit'),
    },
  };
  const actionSuccessMessages: Record<CloudAccountAction, string> = {
    Disconnect: t('actions.disconnect.done'),
    Reverify: t('actions.reverify.done'),
  };

  return (
    <DashboardActionsMenu
      actions={['Reverify', 'Disconnect'] satisfies CloudAccountAction[]}
      ariaLabel={tActions('openActionsFor', { name: getCloudProviderLabel(account.provider) })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('actions.failed'))}
      getActionSuccessMessage={(action) => actionSuccessMessages[action]}
      modalContentByAction={cloudAccountActionModalContent}
      onActionConfirm={(action) => onActionConfirm(account, action)}
    />
  );
}
