'use client';

import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import {
  ALL_SIGNAL_TYPES_VALUE,
  resolveStreamSignalTypesSelection,
  STREAM_REAL_SIGNAL_TYPE_VALUES,
} from '@/constants/stream';
import { useStreamOptions } from '@/hooks/dashboard/use-stream-options';
import { StreamFormSchema, type StreamFormInput } from '@/schemas/stream-schemas';

const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const emptyFormValues: StreamFormInput = {
  deliveryMethod: 'Push',
  endpoint: '',
  signalTypes: [ALL_SIGNAL_TYPES_VALUE, ...STREAM_REAL_SIGNAL_TYPE_VALUES],
};

type StreamFormModalProps = {
  defaultValues?: StreamFormInput;
  description: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: StreamFormInput) => void;
  open: boolean;
  primaryActionLabel: string;
  title: string;
};

const streamFormId = 'stream-form';

export function StreamFormModal({
  defaultValues,
  description,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  primaryActionLabel,
  title,
}: StreamFormModalProps) {
  const t = useTranslations('dashboard.streams.form');
  const { deliveryMethodOptions, signalTypeOptions } = useStreamOptions();
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<StreamFormInput>({
    resolver: zodResolver(StreamFormSchema),
    defaultValues: defaultValues ?? emptyFormValues,
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
      primaryActionForm={streamFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form
        id={streamFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((data) => onSubmit(data))}
      >
        <Input
          label={t('endpoint')}
          placeholder="https://api.example.com/security/signals"
          hint={t('endpointHint')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('endpoint')}
          error={errors.endpoint}
          disabled={isSubmitting}
        />

        <Controller
          control={control}
          name="deliveryMethod"
          render={({ field }) => (
            <Select
              label={t('deliveryMethod')}
              hint={field.value === 'Push' ? t('pushHint') : t('pollHint')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={deliveryMethodOptions}
              value={field.value}
              error={errors.deliveryMethod}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />

        <Controller
          control={control}
          name="signalTypes"
          render={({ field }) => (
            <MultiSelect
              label={t('signalTypes')}
              placeholder={t('signalTypesPlaceholder')}
              containerClassName={fieldContainerClassName}
              hint={t('signalTypesHint')}
              className={fieldClassName}
              options={signalTypeOptions}
              value={field.value}
              error={errors.signalTypes?.message}
              disabled={isSubmitting}
              onChange={(nextValues) =>
                field.onChange(resolveStreamSignalTypesSelection(field.value, nextValues))
              }
            />
          )}
        />
      </form>
    </Modal>
  );
}
