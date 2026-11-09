'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { TenantApiKey, TenantApiKeyAction, TenantApiKeyStatus } from '@/types/tenant-api-key';

const tenantApiKeyActionsByStatus: Record<TenantApiKeyStatus, TenantApiKeyAction[]> = {
  Active: ['Pause', 'Revoke'],
  Expired: ['Revoke'],
  Paused: ['Resume', 'Revoke'],
  Revoked: [],
};

const messageGroupByAction = {
  Pause: 'pause',
  Resume: 'resume',
  Revoke: 'revoke',
} as const satisfies Record<TenantApiKeyAction, string>;

type TenantApiKeyActionsMenuProps = {
  apiKey: TenantApiKey;
  canRevoke?: boolean;
  canUpdate?: boolean;
  onActionConfirm: (apiKey: TenantApiKey, action: TenantApiKeyAction) => Promise<void> | void;
};

export function TenantApiKeyActionsMenu({
  apiKey,
  canRevoke = true,
  canUpdate = true,
  onActionConfirm,
}: TenantApiKeyActionsMenuProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const tActions = useTranslations('dashboard.actions');
  const tenantApiKeyActionModalContent: Record<TenantApiKeyAction, DashboardActionModalContent> = {
    Pause: {
      title: t('pause.title'),
      description: t('pause.description'),
      primaryActionLabel: t('pause.submit'),
    },
    Resume: {
      title: t('resume.title'),
      description: t('resume.description'),
      primaryActionLabel: t('resume.submit'),
    },
    Revoke: {
      title: t('revoke.title'),
      description: t('revoke.description'),
      primaryActionLabel: t('revoke.submit'),
    },
  };
  const availableActions = tenantApiKeyActionsByStatus[apiKey.status].filter((action) =>
    action === 'Resume' ? canUpdate : canRevoke,
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: apiKey.name })}
      getActionErrorMessage={(error, action) =>
        getApiErrorMessage(error, t(`${messageGroupByAction[action]}.failed`))
      }
      getActionSuccessMessage={(action) => t(`${messageGroupByAction[action]}.done`)}
      modalContentByAction={tenantApiKeyActionModalContent}
      onActionConfirm={(action) => onActionConfirm(apiKey, action)}
    />
  );
}
