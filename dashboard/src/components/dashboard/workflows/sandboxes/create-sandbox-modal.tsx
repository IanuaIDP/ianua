'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { CreateSandboxSchema, type CreateSandboxFormInput } from '@/schemas/sandbox-schemas';

type CreateSandboxModalProps = {
  isSubmitting: boolean;
  onClose: () => void;
  onSubmit: (input: CreateSandboxFormInput) => void;
  open: boolean;
};

const emptyValues: CreateSandboxFormInput = { name: '', runs: 'python' };
const formId = 'create-sandbox-form';

/** Names a sandbox and picks what it runs, which never changes afterwards. */
export function CreateSandboxModal({
  isSubmitting,
  onClose,
  onSubmit,
  open,
}: CreateSandboxModalProps) {
  const t = useTranslations('dashboard.sandboxes.create');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<CreateSandboxFormInput>({
    defaultValues: emptyValues,
    resolver: zodResolver(CreateSandboxSchema),
  });

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
          name="runs"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isSubmitting}
              hint={t('runsHint')}
              label={t('runs')}
              onChange={field.onChange}
              options={[
                { label: t('python'), value: 'python' },
                { label: t('javascript'), value: 'javascript' },
                { label: t('image'), value: 'image' },
              ]}
              value={field.value}
            />
          )}
        />
      </form>
    </Modal>
  );
}
