'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { DeviceAction, TrustedDevice } from '@/types/device';

type DeviceActionsMenuProps = {
  device: TrustedDevice;
  onRevokeConfirm: (device: TrustedDevice) => Promise<void> | void;
};

export function DeviceActionsMenu({ device, onRevokeConfirm }: DeviceActionsMenuProps) {
  const t = useTranslations('dashboard.settings.security');
  const tActions = useTranslations('dashboard.actions');
  const modalContentByAction: Partial<Record<DeviceAction, DashboardActionModalContent>> = {
    Revoke: {
      title: t('devices.revoke.title'),
      description: t('devices.revoke.description'),
      primaryActionLabel: t('devices.revoke.submit'),
    },
  };

  return (
    <DashboardActionsMenu
      actions={['Revoke']}
      ariaLabel={tActions('openActionsFor', { name: device.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('devices.revoke.failed'))}
      getActionSuccessMessage={() => t('devices.revoke.done')}
      modalContentByAction={modalContentByAction}
      onActionConfirm={() => onRevokeConfirm(device)}
    />
  );
}
