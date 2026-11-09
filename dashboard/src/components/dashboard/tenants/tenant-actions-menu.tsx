'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Tenant, TenantAction, TenantStatus } from '@/types/tenant';

type TenantActionsMenuProps = {
  onActionConfirm: (tenant: Tenant, action: TenantAction) => Promise<void> | void;
  tenant: Tenant;
};

const tenantActionsByStatus: Record<TenantStatus, TenantAction[]> = {
  Active: ['Suspend', 'Archive'],
  Archived: ['Delete forever'],
  Provisioning: [],
  Suspended: ['Restore Access', 'Archive'],
};

/** The confirmation texts of the tenant lifecycle actions, in the current language. */
export function useTenantActionModalContent(): Record<TenantAction, DashboardActionModalContent> {
  const t = useTranslations('dashboard.tenants.actionModals');

  return useMemo(
    () => ({
      Archive: {
        title: t('archive.title'),
        description: t('archive.description'),
        primaryActionLabel: t('archive.primary'),
      },
      'Delete forever': {
        title: t('deleteForever.title'),
        description: t('deleteForever.description'),
        primaryActionLabel: t('deleteForever.primary'),
        confirmationPlaceholder: 'DELETE',
        confirmationValue: 'DELETE',
      },
      'Restore Access': {
        title: t('restoreAccess.title'),
        description: t('restoreAccess.description'),
        primaryActionLabel: t('restoreAccess.primary'),
      },
      Suspend: {
        title: t('suspend.title'),
        description: t('suspend.description'),
        primaryActionLabel: t('suspend.primary'),
      },
    }),
    [t],
  );
}

export function TenantActionsMenu({ onActionConfirm, tenant }: TenantActionsMenuProps) {
  const t = useTranslations('dashboard.tenants');
  const tActions = useTranslations('dashboard.actions');
  const tActionLabels = useLooseTranslations('dashboard.actions.labels');
  const modalContent = useTenantActionModalContent();
  const isDeletionWaiting = Boolean(
    tenant.deletableFrom && new Date(tenant.deletableFrom) > new Date(),
  );
  const availableActions = tenantActionsByStatus[tenant.status].filter(
    (action) => action !== 'Delete forever' || !isDeletionWaiting,
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: tenant.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('updateFailed'))}
      getActionSuccessMessage={(action) => tActions('completed', { action: tActionLabels(action) })}
      modalContentByAction={modalContent}
      onActionConfirm={(action) => onActionConfirm(tenant, action)}
    />
  );
}
