'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { MODEL_PROVIDER_KINDS } from '@/constants/model-provider';
import {
  ConnectModelProviderSchema,
  type ConnectModelProviderInput,
} from '@/schemas/model-provider-schemas';

type ConnectProviderModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: ConnectModelProviderInput) => void;
};

const connectProviderFormId = 'connect-provider-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';
const defaultValues: ConnectModelProviderInput = {
  apiKey: '',
  endpoint: '',
  kind: 'openai',
  model: '',
  name: '',
};

export function ConnectProviderModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
}: ConnectProviderModalProps) {
  const t = useTranslations('dashboard.modelProviders.connectModal');
  const tKinds = useTranslations('dashboard.modelProviders.kinds');
  const kindOptions = MODEL_PROVIDER_KINDS.map((kind) => ({ label: tKinds(kind), value: kind }));
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<ConnectModelProviderInput>({
    resolver: zodResolver(ConnectModelProviderSchema),
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
      primaryActionForm={connectProviderFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={connectProviderFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('name')}
          error={errors.name}
          disabled={isSubmitting}
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <Controller
            control={control}
            name="kind"
            render={({ field }) => (
              <Select
                label={t('kind')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={kindOptions}
                value={field.value}
                error={errors.kind}
                disabled={isSubmitting}
                onChange={field.onChange}
              />
            )}
          />
          <Input
            label={t('model')}
            placeholder="deepseek-chat"
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('model')}
            error={errors.model}
            disabled={isSubmitting}
          />
        </div>
        <Input
          label={t('endpoint')}
          placeholder="https://api.example.com/v1"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('endpoint')}
          error={errors.endpoint}
          disabled={isSubmitting}
        />
        <Input
          label={t('apiKey')}
          placeholder={t('apiKeyPlaceholder')}
          type="password"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          hint={t('apiKeyHint')}
          {...register('apiKey')}
          error={errors.apiKey}
          disabled={isSubmitting}
        />
      </form>
    </Modal>
  );
}
