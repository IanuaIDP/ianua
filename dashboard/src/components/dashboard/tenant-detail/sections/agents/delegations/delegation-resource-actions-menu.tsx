'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';

type DelegationResourceAction = 'Revoke';

type DelegationResourceActionsMenuProps = {
  canRevoke?: boolean;
  delegationId: string;
  relation: string;
  resource: string;
  onRevoke: (delegationId: string, relation: string, resource: string) => Promise<void> | void;
};

export function DelegationResourceActionsMenu({
  canRevoke = true,
  delegationId,
  relation,
  resource,
  onRevoke,
}: DelegationResourceActionsMenuProps) {
  const t = useTranslations('dashboard.delegations');
  const tActions = useTranslations('dashboard.actions');
  const delegationResourceActionModalContent: Record<
    DelegationResourceAction,
    DashboardActionModalContent
  > = {
    Revoke: {
      title: t('resourceRevokeModal.title'),
      description: t('resourceRevokeModal.description'),
      primaryActionLabel: t('resourceRevokeModal.submit'),
      warningTone: 'danger',
    },
  };
  const actions: DelegationResourceAction[] = canRevoke ? ['Revoke'] : [];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: `${relation} / ${resource}` })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.resourceRevokeFailed'))}
      getActionSuccessMessage={() => t('toasts.resourceRevoked')}
      modalContentByAction={delegationResourceActionModalContent}
      onActionConfirm={() => onRevoke(delegationId, relation, resource)}
    />
  );
}
