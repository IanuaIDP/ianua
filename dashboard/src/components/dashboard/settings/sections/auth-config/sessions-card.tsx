'use client';

import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Input } from '@/components/ui/Input';

import type { AuthConfigCardProps } from './shared-card-props';

type SessionsCardProps = Pick<AuthConfigCardProps, 'errors' | 'isBusy' | 'register'> & {
  description: string;
};

export function SessionsCard({ description, errors, isBusy, register }: SessionsCardProps) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <SettingsCard title={t('sessions.title')} description={description}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Input
          label={t('sessions.length')}
          type="number"
          containerClassName="mb-0"
          className="bg-cardBg"
          hint={t('sessions.lengthHint')}
          {...register('sessionLifetimeSecs', { valueAsNumber: true })}
          error={errors.sessionLifetimeSecs}
          disabled={isBusy}
        />
        <Input
          label={t('sessions.idle')}
          type="number"
          containerClassName="mb-0"
          className="bg-cardBg"
          hint={t('sessions.idleHint')}
          {...register('idleTimeoutSecs', { valueAsNumber: true })}
          error={errors.idleTimeoutSecs}
          disabled={isBusy}
        />
      </div>
    </SettingsCard>
  );
}
