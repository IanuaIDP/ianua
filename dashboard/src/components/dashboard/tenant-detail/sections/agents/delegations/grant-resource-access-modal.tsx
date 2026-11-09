'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import {
  GrantResourceAccessSchema,
  type GrantResourceAccessInput,
} from '@/schemas/delegation-schemas';

type GrantResourceAccessModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: GrantResourceAccessInput) => void;
};

const grantResourceAccessFormId = 'grant-resource-access-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: GrantResourceAccessInput = {
  relation: '',
  resource: '',
};

export function GrantResourceAccessModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
}: GrantResourceAccessModalProps) {
  const t = useTranslations('dashboard.delegations.resourceModal');
  const { resourceRelationOptions } = useDelegationText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<GrantResourceAccessInput>({
    resolver: zodResolver(GrantResourceAccessSchema),
    defaultValues,
  });

  useEffect(() => {
    if (!open) {
      reset(defaultValues);
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
      primaryActionForm={grantResourceAccessFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={grantResourceAccessFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Controller
          control={control}
          name="relation"
          render={({ field }) => (
            <Select
              label={t('relation')}
              placeholder={t('relationPlaceholder')}
              hint={t('relationHint')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={resourceRelationOptions}
              value={field.value}
              error={errors.relation}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />

        <Input
          label={t('resource')}
          placeholder="ledger:2026-q1"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('resource')}
          error={errors.resource}
          disabled={isSubmitting}
        />
      </form>
    </Modal>
  );
}
