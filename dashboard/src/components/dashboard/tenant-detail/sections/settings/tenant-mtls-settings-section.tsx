'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { ReenteredProofModal } from '@/components/dashboard/shared/reentered-proof-modal';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantMtlsConfig,
  updateTenantMtlsConfig,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { MtlsConfigSchema, type MtlsConfigInput } from '@/schemas/mtls-schemas';
import type { ReenteredProof } from '@/types/auth';

const MTLS_MODES = ['Disabled', 'Optional', 'Required'] as const;

const defaultValues: MtlsConfigInput = { mode: 'Disabled', trustedCaCertsText: '' };

export function TenantMtlsSettingsSection() {
  const t = useTranslations('dashboard.tenantSettings.mtls');
  const tErrors = useTranslations('common.errors');
  const mtlsModeOptions = MTLS_MODES.map((mode) => ({ label: t(`modes.${mode}`), value: mode }));
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateMtls = hasPermission('Mtls', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const mtlsQueryKey = ['tenant-mtls', orgSlug, tenantSlug];

  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    reset,
  } = useForm<MtlsConfigInput>({
    resolver: zodResolver(MtlsConfigSchema),
    defaultValues,
  });

  const {
    data: mtlsConfig,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantMtlsConfig(orgSlug ?? '', tenantSlug),
    queryKey: mtlsQueryKey,
  });

  const [pendingUpdate, setPendingUpdate] = useState<MtlsConfigInput | null>(null);
  const {
    error: updateError,
    isPending: isUpdatingMtls,
    mutate: submitMtlsUpdate,
    reset: resetMtlsUpdate,
  } = useMutation({
    mutationFn: ({ payload, proof }: { payload: MtlsConfigInput; proof: ReenteredProof }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantMtlsConfig(orgSlug, tenantSlug, payload, proof);
    },
    onSuccess: async (updatedConfig) => {
      setPendingUpdate(null);
      reset({
        mode: updatedConfig.mode,
        trustedCaCertsText: updatedConfig.trustedCaCerts.join('\n\n'),
      });
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: mtlsQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  useEffect(() => {
    if (!mtlsConfig) {
      return;
    }

    reset({ mode: mtlsConfig.mode, trustedCaCertsText: mtlsConfig.trustedCaCerts.join('\n\n') });
  }, [mtlsConfig, reset]);

  function handleFormSubmit(data: MtlsConfigInput) {
    if (!isDirty) {
      return;
    }

    resetMtlsUpdate();
    setPendingUpdate(data);
  }

  function discardChanges() {
    reset({
      mode: mtlsConfig?.mode ?? defaultValues.mode,
      trustedCaCertsText:
        mtlsConfig?.trustedCaCerts.join('\n\n') ?? defaultValues.trustedCaCertsText,
    });
  }

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const isBusy = isLoading || isUpdatingMtls || !canUpdateMtls;

  return (
    <SettingsCard title={t('title')} description={t('description')}>
      <form className="flex flex-col gap-6" onSubmit={handleSubmit(handleFormSubmit)}>
        <Controller
          control={control}
          name="mode"
          render={({ field }) => (
            <Select
              label={t('mode')}
              containerClassName="mb-0"
              className="bg-cardBg"
              options={mtlsModeOptions}
              value={field.value}
              error={errors.mode}
              disabled={isBusy}
              onChange={field.onChange}
            />
          )}
        />

        <Controller
          control={control}
          name="trustedCaCertsText"
          render={({ field }) => (
            <Textarea
              label={t('certificates')}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              hint={t('certificatesHint')}
              containerClassName="mb-0"
              rows={8}
              value={field.value}
              error={errors.trustedCaCertsText}
              disabled={isBusy}
              onChange={field.onChange}
            />
          )}
        />

        {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}

        <div className="flex items-center gap-4">
          <Button
            type="submit"
            isLoading={isUpdatingMtls}
            disabled={isLoading || !isDirty || Boolean(errorMessage) || !canUpdateMtls}
            className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
          >
            {t('save')}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={isLoading || !isDirty || isUpdatingMtls}
            onClick={discardChanges}
            className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
          >
            {t('discard')}
          </Button>
        </div>
      </form>

      <ReenteredProofModal
        key={pendingUpdate ? 'mtls-proof-open' : 'mtls-proof-closed'}
        description={t('proofDescription')}
        error={updateError}
        errorFallback={t('toasts.updateFailed')}
        isSubmitting={isUpdatingMtls}
        open={Boolean(pendingUpdate)}
        onClose={() => setPendingUpdate(null)}
        onSubmit={(proof) => {
          if (pendingUpdate) {
            submitMtlsUpdate({ payload: pendingUpdate, proof });
          }
        }}
      />
    </SettingsCard>
  );
}
