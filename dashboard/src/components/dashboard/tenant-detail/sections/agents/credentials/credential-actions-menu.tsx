'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useCredentialText } from '@/hooks/dashboard/use-credential-text';
import { getApiErrorMessage } from '@/lib/api';
import type { Credential, CredentialAction } from '@/types/credential';

type CredentialActionsMenuProps = {
  canRevoke: boolean;
  credential: Credential;
  onActionConfirm: (credential: Credential, action: CredentialAction) => Promise<void> | void;
};

export function CredentialActionsMenu({
  canRevoke,
  credential,
  onActionConfirm,
}: CredentialActionsMenuProps) {
  const t = useTranslations('dashboard.credentials');
  const tActions = useTranslations('dashboard.actions');
  const { actionModalContent } = useCredentialText();
  const actions: CredentialAction[] =
    canRevoke && credential.status !== 'Revoked' ? ['Revoke'] : [];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: credential.kid })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={() => t('toasts.revoked')}
      modalContentByAction={actionModalContent(credential)}
      onActionConfirm={(action) => onActionConfirm(credential, action)}
    />
  );
}
