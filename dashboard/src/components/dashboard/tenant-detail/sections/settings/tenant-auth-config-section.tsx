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
import { Switch } from '@/components/ui/Switch';
import { AUTH_METHOD_ORDER, DEFAULT_AUTH_CONFIG } from '@/constants/auth-config';
import { useAuthConfigOptions } from '@/hooks/dashboard/use-auth-config-options';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { deriveErrorMessage, getApiErrorMessage, getAuthConfig, updateAuthConfig } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ReenteredProof } from '@/types/auth';
import {
  AuthConfigSchema,
  type AuthConfigInput,
  type SharedAuthConfigFields,
} from '@/schemas/auth-config-schemas';

export function TenantAuthConfigSection() {
  const t = useTranslations('dashboard.settings.authConfig');
  const tErrors = useTranslations('common.errors');
  const { authMethodLabels, mfaPolicyOptions } = useAuthConfigOptions();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdate = hasPermission('AuthConfig', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const configQueryKey = ['tenant-auth-config', orgSlug, tenantSlug];

  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<AuthConfigInput>({
    resolver: zodResolver(AuthConfigSchema),
    defaultValues: DEFAULT_AUTH_CONFIG,
  });

  // The shared cards touch only the fields both forms state identically, and
  // this form contains that shape. TypeScript will not narrow a Control on its
  // own, so the three handles are re-typed once here rather than at each card.
  const sharedControl = control as unknown as Control<SharedAuthConfigFields>;
  const sharedErrors = errors as FieldErrors<SharedAuthConfigFields>;
  const sharedRegister = register as unknown as UseFormRegister<SharedAuthConfigFields>;

  const baselineAal = useWatch({ control, name: 'stepUp.baselineAal' });
  const mfaPolicy = useWatch({ control, name: 'mfaPolicy' });
  const everySignInIsChallenged = baselineAal !== 'Aal1';

  const {
    data: config,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getAuthConfig(orgSlug ?? '', tenantSlug),
    queryKey: configQueryKey,
  });

  useEffect(() => {
    if (config) {
      reset(config);
    }
  }, [config, reset]);

  const [pendingConfig, setPendingConfig] = useState<AuthConfigInput | null>(null);
  const {
    error: saveError,
    isPending: isSaving,
    mutate: submitConfig,
    reset: resetSave,
  } = useMutation({
    mutationFn: ({ payload, proof }: { payload: AuthConfigInput; proof: ReenteredProof }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateAuthConfig(orgSlug, tenantSlug, payload, proof);
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
  const isBusy = isLoading || isSaving || !canUpdate;

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
        description={t('tenant.description')}
        isDirty={isDirty}
        isLoading={isLoading}
        isSaving={isSaving}
        onDiscard={() => reset(config ?? DEFAULT_AUTH_CONFIG)}
        submitDisabled={Boolean(errorMessage) || !canUpdate}
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
                methods={AUTH_METHOD_ORDER}
                value={field.value}
                onChange={field.onChange}
              />
            )}
          />

          {errors.enabledMethods ? (
            <p className="mt-3 text-xs font-medium text-error">{errors.enabledMethods.message}</p>
          ) : null}

          <div className="mt-4">
            <Controller
              control={control}
              name="selfRegistration"
              render={({ field }) => (
                <Switch
                  checked={field.value}
                  disabled={isBusy}
                  label={t('tenant.selfRegistration')}
                  description={t('tenant.selfRegistrationHint')}
                  onCheckedChange={field.onChange}
                />
              )}
            />
          </div>
        </SettingsCard>

        <PasswordPolicyCard
          control={sharedControl}
          description={t('tenant.passwordsDescription')}
          errors={sharedErrors}
          isBusy={isBusy}
          register={sharedRegister}
        />

        <SecondFactorCard
          control={sharedControl}
          errors={sharedErrors}
          isBusy={isBusy}
          policyHint={
            mfaPolicy === 'Required' ? t('tenant.policyHintRequired') : t('secondFactor.policyHint')
          }
          policyOptions={mfaPolicyOptions}
          sensitiveHint={t('tenant.sensitiveHint')}
          unconditionalWarning={
            everySignInIsChallenged ? (
              <p className="rounded-md border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange">
                {t('tenant.unconditionalWarning')}
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

          <LockoutCard errors={sharedErrors} isBusy={isBusy} register={sharedRegister} />
        </div>

        <AllowedAddressesCard control={sharedControl} isBusy={isBusy} />

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
