'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import Link from 'next/link';
import { Controller, useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { ClearanceSelect } from '@/components/dashboard/workflows/clearance-select';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { CreateMemorySchema, type CreateMemoryFormInput } from '@/schemas/memory-schemas';
import type { ModelProvider } from '@/types/model-provider';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

type CreateMemoryModalProps = {
  isSubmitting: boolean;
  onClose: () => void;
  onSubmit: (input: CreateMemoryFormInput) => void;
  open: boolean;
  providers: ModelProvider[];
};

const emptyValues: CreateMemoryFormInput = {
  clearance: 'internal',
  name: '',
  providerId: '',
};
const formId = 'create-memory-form';

/** Names a memory, picks what fills it and how sensitive its texts may be. */
export function CreateMemoryModal({
  isSubmitting,
  onClose,
  onSubmit,
  open,
  providers,
}: CreateMemoryModalProps) {
  const t = useTranslations('dashboard.memories.create');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<CreateMemoryFormInput>({
    defaultValues: emptyValues,
    resolver: zodResolver(CreateMemorySchema),
  });
  const embeddingProviders = providers.filter(
    (provider) => provider.status === 'Active' && provider.embeddingModel,
  );

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      reset(emptyValues);
    }
  }

  return (
    <Modal
      description={t('description')}
      isPrimaryActionDisabled={isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onClose={onClose}
      open={open}
      primaryActionForm={formId}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      showCloseButton={false}
      title={t('title')}
    >
      <form
        id={formId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((values) => onSubmit(values))}
      >
        <Input
          {...register('name')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isSubmitting}
          error={errors.name}
          label={t('name')}
          placeholder={t('namePlaceholder')}
        />
        <Controller
          control={control}
          name="providerId"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isSubmitting}
              hint={
                <>
                  {t('filledByHint')}{' '}
                  <Link
                    className="font-semibold text-primary hover:underline"
                    href={getTenantScopedPath(
                      isTenantView,
                      orgSlug,
                      tenantSlug,
                      'model-providers',
                      'model-providers',
                    )}
                  >
                    {t('filledByLink')}
                  </Link>
                </>
              }
              label={t('filledBy')}
              onChange={field.onChange}
              options={[
                { label: t('platform'), value: '' },
                ...embeddingProviders.map((provider) => ({
                  label: `${provider.name} (${provider.embeddingModel})`,
                  value: provider.id,
                })),
              ]}
              value={field.value}
            />
          )}
        />
        <Controller
          control={control}
          name="clearance"
          render={({ field }) => (
            <ClearanceSelect label={t('clearance')} onChange={field.onChange} value={field.value} />
          )}
        />
      </form>
    </Modal>
  );
}
