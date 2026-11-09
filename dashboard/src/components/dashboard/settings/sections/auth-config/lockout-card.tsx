'use client';

import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Input } from '@/components/ui/Input';

import type { AuthConfigCardProps } from './shared-card-props';

type LockoutCardProps = Pick<AuthConfigCardProps, 'errors' | 'isBusy' | 'register'> & {
  lockoutHint?: ReactNode;
};

export function LockoutCard({ errors, isBusy, lockoutHint, register }: LockoutCardProps) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <SettingsCard title={t('lockout.title')} description={t('lockout.description')}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Input
          label={t('lockout.attempts')}
          type="number"
          containerClassName="mb-0"
          className="bg-cardBg"
          {...register('maxLoginAttempts', { valueAsNumber: true })}
          error={errors.maxLoginAttempts}
          disabled={isBusy}
        />
        <Input
          label={t('lockout.duration')}
          type="number"
          containerClassName="mb-0"
          className="bg-cardBg"
          hint={lockoutHint}
          {...register('lockoutDurationSecs', { valueAsNumber: true })}
          error={errors.lockoutDurationSecs}
          disabled={isBusy}
        />
      </div>
    </SettingsCard>
  );
}
