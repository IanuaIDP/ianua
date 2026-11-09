'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select, type SelectOption } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { TenantAgentFormSchema, type TenantAgentFormInput } from '@/schemas/tenant-agent-schemas';

const emptyFormValues: TenantAgentFormInput = { description: '', name: '', ownerId: '' };

type TenantAgentFormModalProps = {
  defaultValues?: TenantAgentFormInput;
  description: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: TenantAgentFormInput) => void;
  open: boolean;
  ownerOptions?: SelectOption[];
  primaryActionLabel: string;
  title: string;
};

const tenantAgentFormId = 'tenant-agent-form';

export function TenantAgentFormModal({
  defaultValues,
  description,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  ownerOptions,
  primaryActionLabel,
  title,
}: TenantAgentFormModalProps) {
  const t = useTranslations('dashboard.agents.form');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<TenantAgentFormInput>({
    resolver: zodResolver(TenantAgentFormSchema),
    defaultValues: defaultValues ?? emptyFormValues,
    mode: 'onBlur',
  });

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      reset(defaultValues ?? emptyFormValues);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      primaryActionLabel={primaryActionLabel}
      primaryActionType="submit"
      primaryActionForm={tenantAgentFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form id={tenantAgentFormId} className="flex flex-col" onSubmit={handleSubmit(onSubmit)}>
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          containerClassName="mb-4"
          {...register('name')}
          error={errors.name}
          disabled={isSubmitting}
        />
        <Textarea
          label={t('description')}
          placeholder={t('descriptionPlaceholder')}
          containerClassName={ownerOptions ? 'mb-4' : 'mb-0'}
          rows={3}
          {...register('description')}
          error={errors.description}
          disabled={isSubmitting}
        />
        {ownerOptions ? (
          <Controller
            control={control}
            name="ownerId"
            render={({ field }) => (
              <Select
                label={t('owner')}
                placeholder={t('ownerPlaceholder')}
                containerClassName="mb-0"
                hint={t('ownerHint')}
                options={ownerOptions}
                value={field.value ?? ''}
                error={errors.ownerId}
                disabled={isSubmitting}
                onChange={field.onChange}
              />
            )}
          />
        ) : null}
      </form>
    </Modal>
  );
}
