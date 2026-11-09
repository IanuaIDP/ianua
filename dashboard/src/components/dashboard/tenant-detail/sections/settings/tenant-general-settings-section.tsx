'use client';

import { useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getLocales,
  getTenant,
  getTimezones,
  updateTenantSettings,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  TenantSettingsGeneralSchema,
  type TenantSettingsGeneralInput,
} from '@/schemas/tenant-schemas';
import { useAuthStore } from '@/store/auth-store';

const tenantDefaultValues: TenantSettingsGeneralInput = {
  contactEmail: '',
  displayName: '',
  locale: '',
  timezone: '',
};

export function TenantGeneralSettingsSection() {
  const t = useTranslations('dashboard.tenantSettings.general');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateSettings = hasPermission('TenantSettings', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const updateUser = useAuthStore((state) => state.updateUser);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<TenantSettingsGeneralInput>({
    resolver: zodResolver(TenantSettingsGeneralSchema),
    defaultValues: tenantDefaultValues,
    mode: 'onBlur',
  });
  const {
    data: tenant,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenant(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-detail', orgSlug, tenantSlug],
  });
  const { data: timezoneOptions = [], isLoading: isLoadingTimezones } = useQuery({
    queryFn: getTimezones,
    queryKey: ['timezones'],
    staleTime: Infinity,
  });
  const { data: localeOptions = [], isLoading: isLoadingLocales } = useQuery({
    queryFn: getLocales,
    queryKey: ['locales'],
    staleTime: Infinity,
  });
  const { isPending: isUpdatingTenant, mutate: submitTenantUpdate } = useMutation({
    mutationFn: (payload: TenantSettingsGeneralInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantSettings(orgSlug, tenantSlug, {
        ...payload,
        primaryDomain: tenant?.primaryDomain ?? null,
      });
    },
    onSuccess: async (updatedTenant) => {
      updateUser({ tenantName: updatedTenant.displayName });
      reset({
        contactEmail: updatedTenant.contactEmail,
        displayName: updatedTenant.displayName,
        locale: updatedTenant.locale,
        timezone: updatedTenant.timezone,
      });
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-detail', orgSlug, tenantSlug] });
      await queryClient.invalidateQueries({ queryKey: ['tenant-metrics', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  useEffect(() => {
    if (!tenant) {
      return;
    }

    reset({
      contactEmail: tenant.contactEmail,
      displayName: tenant.displayName,
      locale: tenant.locale,
      timezone: tenant.timezone,
    });
  }, [tenant, reset]);

  function handleTenantSubmit(data: TenantSettingsGeneralInput) {
    if (!isDirty) {
      return;
    }

    submitTenantUpdate(data);
  }

  function discardTenantChanges() {
    reset({
      contactEmail: tenant?.contactEmail ?? tenantDefaultValues.contactEmail,
      displayName: tenant?.displayName ?? tenantDefaultValues.displayName,
      locale: tenant?.locale ?? tenantDefaultValues.locale,
      timezone: tenant?.timezone ?? tenantDefaultValues.timezone,
    });
  }

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const isBusy = isLoading || isUpdatingTenant || !canUpdateSettings;

  return (
    <SettingsCard title={t('title')} description={t('description')}>
      <form className="space-y-6" onSubmit={handleSubmit(handleTenantSubmit)}>
        <div className="grid gap-4 md:grid-cols-2">
          <Input
            label={t('name')}
            placeholder={t('namePlaceholder')}
            containerClassName="mb-0"
            {...register('displayName')}
            error={errors.displayName}
            disabled={isBusy}
          />
          <Input
            label={t('contactEmail')}
            placeholder={t('contactEmailPlaceholder')}
            type="email"
            containerClassName="mb-0"
            {...register('contactEmail')}
            error={errors.contactEmail}
            disabled={isBusy}
          />
          <Controller
            control={control}
            name="timezone"
            render={({ field }) => (
              <Select
                label={t('timezone')}
                containerClassName="mb-0"
                className="bg-cardBg"
                options={timezoneOptions}
                value={field.value}
                error={errors.timezone}
                disabled={isBusy || isLoadingTimezones}
                onChange={field.onChange}
              />
            )}
          />
          <Controller
            control={control}
            name="locale"
            render={({ field }) => (
              <Select
                label={t('locale')}
                containerClassName="mb-0"
                className="bg-cardBg"
                options={localeOptions}
                value={field.value}
                error={errors.locale}
                disabled={isBusy || isLoadingLocales}
                onChange={field.onChange}
              />
            )}
          />
          {tenant?.environment ? (
            <Input
              label={t('environment')}
              hint={t('cannotChange')}
              containerClassName="mb-0"
              value={tenant.environment}
              disabled
              readOnly
            />
          ) : null}
          <Input
            label={t('slug')}
            hint={t('cannotChange')}
            containerClassName="mb-0"
            value={tenant?.slug ?? ''}
            readOnly
            disabled
          />
          <Input
            label={t('domain')}
            hint={t('cannotChange')}
            containerClassName="mb-0"
            value={tenant?.primaryDomain ?? ''}
            readOnly
            disabled
          />
        </div>
        {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}

        <div className="flex items-center gap-4">
          <Button
            type="submit"
            isLoading={isUpdatingTenant}
            disabled={isLoading || !isDirty || Boolean(errorMessage) || !canUpdateSettings}
            className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
          >
            {t('save')}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={isLoading || !isDirty || isUpdatingTenant}
            onClick={discardTenantChanges}
            className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
          >
            {t('discard')}
          </Button>
        </div>
      </form>
    </SettingsCard>
  );
}
