'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Passkey, PasskeyAction } from '@/types/passkey';

const customPasskeyActions: PasskeyAction[] = ['Rename'];

type PasskeyActionsMenuProps = {
  onRemoveConfirm: (passkey: Passkey) => Promise<void> | void;
  onRenameClick: (passkey: Passkey) => void;
  passkey: Passkey;
};

export function PasskeyActionsMenu({
  onRemoveConfirm,
  onRenameClick,
  passkey,
}: PasskeyActionsMenuProps) {
  const t = useTranslations('dashboard.settings.security');
  const tActions = useTranslations('dashboard.actions');
  const modalContentByAction: Partial<Record<PasskeyAction, DashboardActionModalContent>> = {
    Remove: {
      title: t('passkeys.remove.title'),
      description: t('passkeys.remove.description'),
      primaryActionLabel: t('passkeys.remove.submit'),
    },
  };

  return (
    <DashboardActionsMenu
      actions={['Rename', 'Remove']}
      ariaLabel={tActions('openActionsFor', { name: passkey.name })}
      customActions={customPasskeyActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('passkeys.remove.failed'))}
      getActionSuccessMessage={() => t('passkeys.remove.done')}
      modalContentByAction={modalContentByAction}
      onActionConfirm={() => onRemoveConfirm(passkey)}
      onCustomAction={(action) => {
        if (action === 'Rename') {
          onRenameClick(passkey);
        }
      }}
    />
  );
}
