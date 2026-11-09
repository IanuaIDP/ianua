'use client';

import type { ReactNode } from 'react';
import { Controller } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Textarea } from '@/components/ui/Textarea';

import type { AuthConfigCardProps } from './shared-card-props';

type AllowedAddressesCardProps = Pick<AuthConfigCardProps, 'control' | 'isBusy'> & {
  warning?: ReactNode;
};

export function AllowedAddressesCard({ control, isBusy, warning }: AllowedAddressesCardProps) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <SettingsCard title={t('addresses.title')} description={t('addresses.description')}>
      <Controller
        control={control}
        name="ipAllowlist"
        render={({ field }) => (
          <Textarea
            label={t('addresses.label')}
            placeholder="10.0.0.0/8&#10;192.168.1.0/24"
            hint={t('addresses.hint')}
            containerClassName="mb-0"
            rows={4}
            value={field.value.join('\n')}
            disabled={isBusy}
            onChange={(event) =>
              field.onChange(
                event.target.value
                  .split('\n')
                  .map((line) => line.trim())
                  .filter(Boolean),
              )
            }
          />
        )}
      />

      {warning}
    </SettingsCard>
  );
}
