'use client';

import { Controller } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';

import type { AuthConfigCardProps } from './shared-card-props';

const BREACHED_PASSWORD_ACTIONS = ['Off', 'Warn', 'Block'] as const;

type PasswordPolicyCardProps = AuthConfigCardProps & {
  description: string;
};

export function PasswordPolicyCard({
  control,
  description,
  errors,
  isBusy,
  register,
}: PasswordPolicyCardProps) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <SettingsCard title={t('passwords.title')} description={description}>
      <div className="flex flex-col gap-4">
        <Input
          label={t('passwords.minLength')}
          type="number"
          containerClassName="mb-0"
          className="max-w-40 bg-cardBg"
          {...register('passwordPolicy.minLength', { valueAsNumber: true })}
          error={errors.passwordPolicy?.minLength}
          disabled={isBusy}
        />

        <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
          <Checkbox
            label={t('passwords.uppercase')}
            disabled={isBusy}
            {...register('passwordPolicy.require.uppercase')}
          />
          <Checkbox
            label={t('passwords.lowercase')}
            disabled={isBusy}
            {...register('passwordPolicy.require.lowercase')}
          />
          <Checkbox
            label={t('passwords.digit')}
            disabled={isBusy}
            {...register('passwordPolicy.require.digit')}
          />
          <Checkbox
            label={t('passwords.special')}
            disabled={isBusy}
            {...register('passwordPolicy.require.special')}
          />
        </div>

        <Controller
          control={control}
          name="breachedPasswords"
          render={({ field }) => (
            <Select
              label={t('passwords.breached')}
              hint={t('passwords.breachedHint')}
              containerClassName="mb-0"
              className="max-w-40 bg-cardBg"
              options={BREACHED_PASSWORD_ACTIONS.map((action) => ({
                label: t(`passwords.breachedActions.${action}`),
                value: action,
              }))}
              value={field.value ?? 'Off'}
              disabled={isBusy}
              onChange={field.onChange}
            />
          )}
        />
      </div>
    </SettingsCard>
  );
}
