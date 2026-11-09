'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';
import type { Control, FieldErrors, UseFormRegister } from 'react-hook-form';

import { AllowedAddressesCard } from '@/components/dashboard/settings/sections/auth-config/allowed-addresses-card';
import { AuthConfigHeader } from '@/components/dashboard/settings/sections/auth-config/auth-config-header';
import { AuthMethodToggleGroup } from '@/components/dashboard/settings/sections/auth-config/auth-method-toggle-group';
import { LockoutCard } from '@/components/dashboard/settings/sections/auth-config/lockout-card';
import { PasswordPolicyCard } from '@/components/dashboard/settings/sections/auth-config/password-policy-card';
import { SecondFactorCard } from '@/components/dashboard/settings/sections/auth-config/second-factor-card';
import { SessionsCard } from '@/components/dashboard/settings/sections/auth-config/sessions-card';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { ReenteredProofModal } from '@/components/dashboard/shared/reentered-proof-modal';
import { useNotification } from '@/components/ui/notifications';
import { DEFAULT_ORG_AUTH_CONFIG, ORG_AUTH_METHOD_ORDER } from '@/constants/auth-config';
import { useAuthConfigOptions } from '@/hooks/dashboard/use-auth-config-options';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getOrgAuthConfig,
  updateOrgAuthConfig,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ReenteredProof } from '@/types/auth';
import {
  OrgAuthConfigSchema,
  type OrgAuthConfigInput,
  type SharedAuthConfigFields,
} from '@/schemas/auth-config-schemas';
import { useAuthStore } from '@/store/auth-store';

export function OrgAuthConfigSection() {
  const t = useTranslations('dashboard.settings.authConfig');
  const tErrors = useTranslations('common.errors');
  const { authMethodLabels, orgMfaPolicyOptions } = useAuthConfigOptions();
  const orgSlug = useAuthStore((state) => state.user?.organizationSlug);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const configQueryKey = ['org-auth-config', orgSlug];

  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<OrgAuthConfigInput>({
    resolver: zodResolver(OrgAuthConfigSchema),
    defaultValues: DEFAULT_ORG_AUTH_CONFIG,
  });

  // The shared cards touch only the fields both forms state identically, and
  // this form contains that shape. TypeScript will not narrow a Control on its
  // own, so the three handles are re-typed once here rather than at each card.
  const sharedControl = control as unknown as Control<SharedAuthConfigFields>;
  const sharedErrors = errors as FieldErrors<SharedAuthConfigFields>;
  const sharedRegister = register as unknown as UseFormRegister<SharedAuthConfigFields>;

  const baselineAal = useWatch({ control, name: 'stepUp.baselineAal' });
  const mfaPolicy = useWatch({ control, name: 'mfaPolicy' });
  const ipAllowlist = useWatch({ control, name: 'ipAllowlist' });
  const hasAddressRestrictions = (ipAllowlist ?? []).length > 0;
  // Two different settings reach the same place: a second factor on every
  // sign-in, which leaves the device and country rules with nothing to decide
  // and makes trusting a device pointless.
  const twoFactorIsAlreadyUnconditional = mfaPolicy === 'Required' || baselineAal !== 'Aal1';

  const {
    data: config,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getOrgAuthConfig(orgSlug ?? ''),
    queryKey: configQueryKey,
  });

  useEffect(() => {
    if (config) {
      reset(config);
    }
  }, [config, reset]);

  const [pendingConfig, setPendingConfig] = useState<OrgAuthConfigInput | null>(null);
  const {
    error: saveError,
    isPending: isSaving,
    mutate: submitConfig,
    reset: resetSave,
  } = useMutation({
    mutationFn: ({ payload, proof }: { payload: OrgAuthConfigInput; proof: ReenteredProof }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateOrgAuthConfig(orgSlug, payload, proof);
    },
    onSuccess: async () => {
      setPendingConfig(null);
      showNotification({ message: t('updated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: configQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const isBusy = isLoading || isSaving;

  return (
    <form
      className="flex h-full w-full flex-col overflow-hidden rounded-lg border border-borderGray bg-cardBg"
      onSubmit={handleSubmit((payload) => {
        resetSave();
        setPendingConfig(payload);
      })}
    >
      <AuthConfigHeader
        title={t('title')}
        description={t('org.description')}
        isDirty={isDirty}
        isLoading={isLoading}
        isSaving={isSaving}
        onDiscard={() => reset(config ?? DEFAULT_ORG_AUTH_CONFIG)}
        submitDisabled={Boolean(errorMessage)}
      />

      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 py-4">
        <SettingsCard title={t('waysIn.title')} description={t('waysIn.description')}>
          <Controller
            control={control}
            name="enabledMethods"
            render={({ field }) => (
              <AuthMethodToggleGroup
                disabled={isBusy}
                labels={authMethodLabels}
                methods={ORG_AUTH_METHOD_ORDER}
                value={field.value}
                onChange={field.onChange}
              />
            )}
          />

          {errors.enabledMethods ? (
            <p className="mt-3 text-xs font-medium text-error">{errors.enabledMethods.message}</p>
          ) : null}
        </SettingsCard>

        <PasswordPolicyCard
          control={sharedControl}
          description={t('org.passwordsDescription')}
          errors={sharedErrors}
          isBusy={isBusy}
          register={sharedRegister}
        />

        <SecondFactorCard
          control={sharedControl}
          errors={sharedErrors}
          isBusy={isBusy}
          policyHint={
            mfaPolicy === 'Disabled' ? t('org.policyHintOff') : t('secondFactor.policyHint')
          }
          policyOptions={orgMfaPolicyOptions}
          sensitiveHint={t('org.sensitiveHint')}
          unconditionalWarning={
            twoFactorIsAlreadyUnconditional ? (
              <p className="rounded-md border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange">
                {t('org.unconditionalWarning')}
              </p>
            ) : null
          }
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <SessionsCard
            description={t('sessions.description')}
            errors={sharedErrors}
            isBusy={isBusy}
            register={sharedRegister}
          />

          <LockoutCard
            errors={sharedErrors}
            isBusy={isBusy}
            lockoutHint={t('org.lockoutHint')}
            register={sharedRegister}
          />
        </div>

        <AllowedAddressesCard
          control={sharedControl}
          isBusy={isBusy}
          warning={
            hasAddressRestrictions ? (
              <p className="mt-3 rounded-md border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange">
                {t('org.addressWarning')}
              </p>
            ) : null
          }
        />

        {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}
      </div>

      <ReenteredProofModal
        key={pendingConfig ? 'auth-config-proof-open' : 'auth-config-proof-closed'}
        description={t('proofDescription')}
        error={saveError}
        errorFallback={t('saveFailed')}
        isSubmitting={isSaving}
        open={Boolean(pendingConfig)}
        onClose={() => setPendingConfig(null)}
        onSubmit={(proof) => {
          if (pendingConfig) {
            submitConfig({ payload: pendingConfig, proof });
          }
        }}
      />
    </form>
  );
}
