'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Domain, DomainAction } from '@/types/domain';

type DomainActionsMenuProps = {
  canDelete?: boolean;
  canTransfer?: boolean;
  canUpdate?: boolean;
  domain: Domain;
  onActionConfirm: (domain: Domain, action: DomainAction) => Promise<void> | void;
  onTransfer: (domain: Domain) => void;
  onViewInstructions: (domain: Domain) => void;
};

export function DomainActionsMenu({
  canDelete = true,
  canTransfer = true,
  canUpdate = true,
  domain,
  onActionConfirm,
  onTransfer,
  onViewInstructions,
}: DomainActionsMenuProps) {
  const t = useTranslations('dashboard.domains');
  const tActions = useTranslations('dashboard.actions');
  const tSuccess = useLooseTranslations('dashboard.domains.actionSuccess');
  const domainActionModalContent: Partial<Record<DomainAction, DashboardActionModalContent>> = {
    Delete: {
      title: t('deleteModal.title'),
      description: t('deleteModal.description'),
      primaryActionLabel: t('deleteModal.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
    },
  };
  const canProvisionTls =
    canUpdate &&
    !domain.isAutoVerified &&
    domain.verificationStatus === 'Verified' &&
    (domain.tlsStatus === 'NotRequired' || domain.tlsStatus === 'Expired');
  const canVerify = canUpdate && domain.verificationStatus === 'Pending';
  const canViewInstructions = canUpdate && domain.verificationStatus === 'Pending';

  const actions: DomainAction[] = [
    ...(canViewInstructions ? (['ViewInstructions'] as const) : []),
    ...(canVerify ? (['Verify'] as const) : []),
    ...(canProvisionTls ? (['ProvisionTls'] as const) : []),
    ...(canTransfer ? (['Transfer'] as const) : []),
    ...(canDelete ? (['Delete'] as const) : []),
  ];
  const instantActions = actions.filter(
    (action) => action === 'ProvisionTls' || action === 'Verify',
  );
  const customActions = actions.filter(
    (action) => action === 'ViewInstructions' || action === 'Transfer',
  );

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: domain.domain })}
      customActions={customActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        tSuccess.has(action) ? tSuccess(action) : tActions('succeeded')
      }
      instantActions={instantActions}
      modalContentByAction={domainActionModalContent}
      onActionConfirm={(action) => onActionConfirm(domain, action)}
      onCustomAction={(action) => {
        if (action === 'ViewInstructions') {
          onViewInstructions(domain);
        }

        if (action === 'Transfer') {
          onTransfer(domain);
        }
      }}
    />
  );
}
