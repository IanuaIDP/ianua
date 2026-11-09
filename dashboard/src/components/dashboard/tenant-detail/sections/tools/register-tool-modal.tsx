'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { TOOL_METHOD_OPTIONS } from '@/constants/tool';
import { RegisterToolSchema, type RegisterToolInput } from '@/schemas/tool-schemas';

type RegisterToolModalProps = {
  isSubmitting?: boolean;
  routeOptions: { label: string; value: string }[];
  open: boolean;
  onClose: () => void;
  onSubmit: (data: RegisterToolInput) => void;
};

const registerToolFormId = 'register-tool-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: RegisterToolInput = {
  description: '',
  method: 'GET',
  name: '',
  path: '',
  routeId: '',
  schema: '',
};

export function RegisterToolModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
  routeOptions,
}: RegisterToolModalProps) {
  const t = useTranslations('dashboard.tools.registerModal');
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<RegisterToolInput>({
    resolver: zodResolver(RegisterToolSchema),
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
      primaryActionForm={registerToolFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={registerToolFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Input
          label={t('name')}
          placeholder="get_order"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          hint={t('nameHint')}
          {...register('name')}
          error={errors.name}
          disabled={isSubmitting}
        />
        <Textarea
          label={t('descriptionLabel')}
          placeholder={t('descriptionPlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          rows={3}
          {...register('description')}
          error={errors.description}
          disabled={isSubmitting}
        />
        <div className="grid gap-4 sm:grid-cols-2">
          <Controller
            control={control}
            name="method"
            render={({ field }) => (
              <Select
                label={t('method')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={TOOL_METHOD_OPTIONS}
                value={field.value}
                error={errors.method}
                disabled={isSubmitting}
                onChange={field.onChange}
              />
            )}
          />
        </div>
        <Controller
          control={control}
          name="routeId"
          render={({ field }) => (
            <Select
              label={t('route')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={routeOptions}
              placeholder={t('routePlaceholder')}
              value={field.value}
              error={errors.routeId}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
        <Input
          label={t('path')}
          placeholder="/orders/{id}"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('path')}
          error={errors.path}
          disabled={isSubmitting}
        />
        <Textarea
          label={t('schema')}
          placeholder={'{\n  "type": "object",\n  "properties": {}\n}'}
          containerClassName={fieldContainerClassName}
          className={`${fieldClassName} font-mono`}
          rows={5}
          {...register('schema')}
          error={errors.schema}
          disabled={isSubmitting}
        />
      </form>
    </Modal>
  );
}
