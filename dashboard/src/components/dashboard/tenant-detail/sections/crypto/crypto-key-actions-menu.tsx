'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { CryptoKey, CryptoKeyAction } from '@/types/crypto';
import type { DashboardActionModalContent } from '@/types/dashboard';

type CryptoKeyActionsMenuProps = {
  canRevoke?: boolean;
  cryptoKey: CryptoKey;
  onActionConfirm: (cryptoKey: CryptoKey, action: CryptoKeyAction) => Promise<void> | void;
};

const cryptoKeyActions: CryptoKeyAction[] = ['Revoke'];

export function CryptoKeyActionsMenu({
  canRevoke = true,
  cryptoKey,
  onActionConfirm,
}: CryptoKeyActionsMenuProps) {
  const t = useTranslations('dashboard.crypto.keys');
  const tActions = useTranslations('dashboard.actions');
  const cryptoKeyActionModalContent: Record<CryptoKeyAction, DashboardActionModalContent> = {
    Revoke: {
      title: t('revokeModal.title'),
      description: t('revokeModal.description'),
      primaryActionLabel: t('revokeModal.submit'),
      confirmationPlaceholder: 'REVOKE',
      confirmationValue: 'REVOKE',
      warningNote: t('revokeModal.warning'),
      warningTone: 'danger',
    },
  };
  const actions = canRevoke && cryptoKey.status !== 'Revoked' ? cryptoKeyActions : [];

  if (actions.length === 0) {
    return null;
  }

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: cryptoKey.id })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.revokeFailed'))}
      getActionSuccessMessage={() => t('toasts.revoked')}
      modalContentByAction={cryptoKeyActionModalContent}
      onActionConfirm={(action) => onActionConfirm(cryptoKey, action)}
    />
  );
}
