'use client';

import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Controller, FormProvider, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';
import { TenantResidencyFields } from '@/components/dashboard/tenants/tenant-residency-fields';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Modal } from '@/components/ui/modal';
import { getCloudAccounts, getLocales, getTimezones } from '@/lib/api';
import type { CreateTenantInput } from '@/lib/api';
import { CreateTenantSchema } from '@/schemas/tenant-schemas';

type CreateTenantModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CreateTenantInput) => void;
  orgSlug?: string;
};

const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';
const createTenantFormId = 'create-tenant-form';
const defaultResidency: CreateTenantInput['residency'] = {
  isolation: 'Shared',
  kind: 'platform',
};

function toTenantSlug(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^_+|_+$/g, '');
}

export function CreateTenantModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
  orgSlug,
}: CreateTenantModalProps) {
  const t = useTranslations('dashboard.tenants.createModal');
  const form = useForm<CreateTenantInput>({
    resolver: zodResolver(CreateTenantSchema),
    defaultValues: {
      locale: 'en-US',
      residency: defaultResidency,
      timezone: 'UTC',
    },
  });
  const {
    formState: { errors },
    handleSubmit,
    register,
    reset,
    control,
    setValue,
  } = form;
  const displayName = useWatch({
    control,
    name: 'displayName',
  });
  const residencyKind = useWatch({ control, name: 'residency.kind' });
  const { data: timezoneOptions = [], isLoading: isLoadingTimezones } = useQuery({
    enabled: open,
    queryFn: getTimezones,
    queryKey: ['timezones'],
    staleTime: Infinity,
  });
  const { data: localeOptions = [], isLoading: isLoadingLocales } = useQuery({
    enabled: open,
    queryFn: getLocales,
    queryKey: ['locales'],
    staleTime: Infinity,
  });
  const { data: cloudAccounts = [] } = useQuery({
    enabled: open && Boolean(orgSlug),
    queryFn: () => getCloudAccounts(orgSlug ?? ''),
    queryKey: ['cloud-accounts', orgSlug],
  });

  useEffect(() => {
    setValue('slug', toTenantSlug(displayName ?? ''), {
      shouldDirty: true,
      shouldValidate: Boolean(displayName),
    });
  }, [displayName, setValue]);

  useEffect(() => {
    setValue('residency.isolation', residencyKind === 'platform' ? 'Shared' : 'DedicatedInstance', {
      shouldValidate: false,
    });
  }, [residencyKind, setValue]);

  useEffect(() => {
    if (!open) {
      reset();
    }
  }, [open, reset]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={createTenantFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <FormProvider {...form}>
        <form
          id={createTenantFormId}
          className="flex flex-col gap-4"
          onSubmit={handleSubmit(onSubmit)}
        >
          <Input
            label={t('name')}
            placeholder={t('namePlaceholder')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('displayName')}
            error={errors.displayName}
          />
          <Input
            label={t('slug')}
            placeholder={t('slugPlaceholder')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('slug')}
            error={errors.slug}
          />
          <Input
            label={t('contactEmail')}
            placeholder={t('contactEmailPlaceholder')}
            type="email"
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('contactEmail')}
            error={errors.contactEmail}
          />

          <div className="grid gap-4 sm:grid-cols-2">
            <Controller
              control={control}
              name="timezone"
              render={({ field }) => (
                <Select
                  label={t('timezone')}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={timezoneOptions}
                  value={field.value}
                  error={errors.timezone}
                  disabled={isLoadingTimezones}
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
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={localeOptions}
                  value={field.value}
                  error={errors.locale}
                  disabled={isLoadingLocales}
                  onChange={field.onChange}
                />
              )}
            />
          </div>

          <TenantResidencyFields
            connectedProviders={cloudAccounts
              .filter((account) => account.usable)
              .map((account) => account.provider)}
            disabled={isSubmitting}
            orgSlug={orgSlug}
          />
        </form>
      </FormProvider>
    </Modal>
  );
}
