'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { OAuthClient, OAuthClientAction, OAuthClientStatus } from '@/types/oauth-client';

const oauthClientActionsByStatus: Record<OAuthClientStatus, OAuthClientAction[]> = {
  Active: ['Edit', 'Rotate secret', 'Revoke'],
  Revoked: [],
};

const customOAuthClientActions: OAuthClientAction[] = ['Edit'];

type OAuthClientActionsMenuProps = {
  canRevoke?: boolean;
  canUpdate?: boolean;
  client: OAuthClient;
  onActionConfirm: (client: OAuthClient, action: OAuthClientAction) => Promise<void> | void;
  onEditClick: (client: OAuthClient) => void;
};

export function OAuthClientActionsMenu({
  canRevoke = true,
  canUpdate = true,
  client,
  onActionConfirm,
  onEditClick,
}: OAuthClientActionsMenuProps) {
  const t = useTranslations('dashboard.oauthClients');
  const tActions = useTranslations('dashboard.actions');
  const oauthClientActionModalContent: Partial<
    Record<OAuthClientAction, DashboardActionModalContent>
  > = {
    Revoke: {
      title: t('revoke.title'),
      description: t('revoke.description'),
      primaryActionLabel: t('revoke.submit'),
    },
    'Rotate secret': {
      title: t('rotate.title'),
      description: t('rotate.description'),
      primaryActionLabel: t('rotate.submit'),
    },
  };
  const availableActions = oauthClientActionsByStatus[client.status].filter((action) =>
    action === 'Revoke' ? canRevoke : canUpdate,
  );
  const availableCustomActions = customOAuthClientActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: client.name })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error, action) =>
        getApiErrorMessage(
          error,
          action === 'Rotate secret' ? t('toasts.secretRotateFailed') : t('revoke.failed'),
        )
      }
      getActionSuccessMessage={(action) =>
        action === 'Rotate secret' ? t('toasts.secretRotated') : t('revoke.done')
      }
      modalContentByAction={oauthClientActionModalContent}
      onActionConfirm={(action) => onActionConfirm(client, action)}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(client);
        }
      }}
    />
  );
}
