'use client';

import { useTranslations } from 'next-intl';

import { TrustedDevicesTable } from '@/components/dashboard/settings/sections/security/trusted-devices-table';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import type { TrustedDevice } from '@/types/device';

type TrustedDevicesCardProps = {
  devices: TrustedDevice[];
  errorMessage?: string | null;
  isLoading?: boolean;
  onRevokeConfirm: (device: TrustedDevice) => Promise<void> | void;
};

export function TrustedDevicesCard({
  devices,
  errorMessage,
  isLoading = false,
  onRevokeConfirm,
}: TrustedDevicesCardProps) {
  const t = useTranslations('dashboard.settings.security');

  return (
    <SettingsCard
      title={t('devices.title')}
      description={t('devices.description')}
      className="overflow-hidden"
    >
      {errorMessage && (
        <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {errorMessage}
        </p>
      )}

      <div className="-mx-4 -mb-4">
        <TrustedDevicesTable
          devices={devices}
          isLoading={isLoading}
          onRevokeConfirm={onRevokeConfirm}
        />
      </div>
    </SettingsCard>
  );
}
