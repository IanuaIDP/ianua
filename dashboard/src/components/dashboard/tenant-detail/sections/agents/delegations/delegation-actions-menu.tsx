'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Delegation, DelegationAction } from '@/types/delegation';

type DelegationActionsMenuProps = {
  canRevoke?: boolean;
  delegation: Delegation;
  onActionConfirm: (delegation: Delegation, action: DelegationAction) => Promise<void> | void;
};

export function DelegationActionsMenu({
  canRevoke = true,
  delegation,
  onActionConfirm,
}: DelegationActionsMenuProps) {
  const t = useTranslations('dashboard.delegations');
  const tActions = useTranslations('dashboard.actions');
  const delegationActionModalContent: Record<DelegationAction, DashboardActionModalContent> = {
    Revoke: {
      title: t('revokeModal.title'),
      description: t('revokeModal.description'),
      primaryActionLabel: t('revokeModal.submit'),
      warningTone: 'danger',
    },
  };
  const actions: DelegationAction[] =
    delegation.status !== 'Revoked' && canRevoke ? ['Revoke'] : [];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: delegation.delegationId.slice(0, 8) })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.revokeFailed'))}
      getActionSuccessMessage={() => t('toasts.revoked')}
      modalContentByAction={delegationActionModalContent}
      onActionConfirm={(action) => onActionConfirm(delegation, action)}
    />
  );
}
