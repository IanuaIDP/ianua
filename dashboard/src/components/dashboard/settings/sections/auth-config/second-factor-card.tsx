'use client';

import type { ReactNode } from 'react';
import { Controller, useWatch } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { useAuthConfigOptions } from '@/hooks/dashboard/use-auth-config-options';
import type { SelectOption } from '@/types/dashboard';

import type { AuthConfigCardProps } from './shared-card-props';

type SecondFactorCardProps = Pick<AuthConfigCardProps, 'control' | 'errors' | 'isBusy'> & {
  policyOptions: SelectOption[];
  policyHint?: ReactNode;
  sensitiveHint: string;

  unconditionalWarning?: ReactNode;
};

export function SecondFactorCard({
  control,
  errors,
  isBusy,
  policyHint,
  policyOptions,
  sensitiveHint,
  unconditionalWarning,
}: SecondFactorCardProps) {
  const t = useTranslations('dashboard.settings.authConfig');
  const { assuranceLevelOptions, riskLevelOptions } = useAuthConfigOptions();
  const secondFactorsOff = useWatch({ control, name: 'mfaPolicy' }) === 'Disabled';
  const offHint = secondFactorsOff ? t('secondFactor.offHint') : undefined;

  return (
    <SettingsCard title={t('secondFactor.title')} description={t('secondFactor.description')}>
      <div className="flex flex-col gap-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Controller
            control={control}
            name="mfaPolicy"
            render={({ field }) => (
              <Select
                label={t('secondFactor.policy')}
                containerClassName="mb-0"
                className="bg-cardBg"
                hint={policyHint}
                options={policyOptions}
                value={field.value}
                error={errors.mfaPolicy?.message}
                disabled={isBusy}
                onChange={field.onChange}
              />
            )}
          />

          <Controller
            control={control}
            name="stepUp.baselineAal"
            render={({ field }) => (
              <Select
                label={t('secondFactor.baseline')}
                containerClassName="mb-0"
                className="bg-cardBg"
                hint={t('secondFactor.baselineHint')}
                options={assuranceLevelOptions}
                value={field.value}
                disabled={isBusy}
                onChange={field.onChange}
              />
            )}
          />

          <Controller
            control={control}
            name="stepUp.sensitiveAal"
            render={({ field }) => (
              <Select
                label={t('secondFactor.sensitive')}
                containerClassName="mb-0"
                className="bg-cardBg"
                hint={sensitiveHint}
                options={assuranceLevelOptions}
                value={field.value}
                error={errors.stepUp?.sensitiveAal?.message}
                disabled={isBusy}
                onChange={field.onChange}
              />
            )}
          />
        </div>
        <div className="flex flex-col gap-2.5">
          <div className="flex flex-col divide-y divide-borderGray rounded-lg border border-borderGray bg-surfaceChip">
            <div className="px-4 py-4">
              <Controller
                control={control}
                name="stepUp.requireMfaNewDevice"
                render={({ field }) => (
                  <Switch
                    checked={field.value}
                    disabled={isBusy || secondFactorsOff}
                    label={t('secondFactor.newDevice')}
                    description={offHint ?? t('secondFactor.newDeviceHint')}
                    onCheckedChange={field.onChange}
                  />
                )}
              />
            </div>

            <div className="px-4 py-4">
              <Controller
                control={control}
                name="stepUp.requireMfaNewCountry"
                render={({ field }) => (
                  <Switch
                    checked={field.value}
                    disabled={isBusy || secondFactorsOff}
                    label={t('secondFactor.newCountry')}
                    description={offHint ?? t('secondFactor.newCountryHint')}
                    onCheckedChange={field.onChange}
                  />
                )}
              />
            </div>
          </div>
          {unconditionalWarning}
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Controller
            control={control}
            name="stepUp.mfaRiskThreshold"
            render={({ field }) => (
              <Select
                label={t('secondFactor.mfaRisk')}
                containerClassName="mb-0"
                className="bg-cardBg"
                hint={offHint}
                options={riskLevelOptions}
                value={field.value}
                disabled={isBusy || secondFactorsOff}
                onChange={field.onChange}
              />
            )}
          />

          <Controller
            control={control}
            name="stepUp.denyRiskThreshold"
            render={({ field }) => (
              <Select
                label={t('secondFactor.denyRisk')}
                containerClassName="mb-0"
                className="bg-cardBg"
                options={riskLevelOptions}
                value={field.value}
                disabled={isBusy}
                onChange={field.onChange}
              />
            )}
          />
        </div>
      </div>
    </SettingsCard>
  );
}
