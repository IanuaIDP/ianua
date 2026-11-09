'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { ApiKey, ApiKeyAction, ApiKeyStatus } from '@/types/api-key';
import type { DashboardActionModalContent } from '@/types/dashboard';

const apiKeyActionsByStatus: Record<ApiKeyStatus, ApiKeyAction[]> = {
  Active: ['Revoke'],
  Expired: ['Revoke'],
  Revoked: [],
};

type ApiKeyActionsMenuProps = {
  apiKey: ApiKey;
  onActionConfirm: (apiKey: ApiKey, action: ApiKeyAction) => Promise<void> | void;
};

export function ApiKeyActionsMenu({ apiKey, onActionConfirm }: ApiKeyActionsMenuProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const tActions = useTranslations('dashboard.actions');
  const apiKeyActionModalContent: Record<ApiKeyAction, DashboardActionModalContent> = {
    Revoke: {
      title: t('revoke.title'),
      description: t('revoke.description'),
      primaryActionLabel: t('revoke.submit'),
    },
  };

  return (
    <DashboardActionsMenu
      actions={apiKeyActionsByStatus[apiKey.status]}
      ariaLabel={tActions('openActionsFor', { name: apiKey.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('revoke.failed'))}
      getActionSuccessMessage={() => t('revoke.done')}
      modalContentByAction={apiKeyActionModalContent}
      onActionConfirm={(action) => onActionConfirm(apiKey, action)}
    />
  );
}
