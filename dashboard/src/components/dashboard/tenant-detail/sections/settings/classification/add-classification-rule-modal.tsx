'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Modal } from '@/components/ui/modal';
import { DATA_CLASS_LEVEL_ORDER, REDACTION_IDS } from '@/constants/classification';
import {
  ClassificationRuleSchema,
  type ClassificationRuleInput,
} from '@/schemas/classification-schemas';

type AddClassificationRuleModalProps = {
  errorMessage?: string | null;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: ClassificationRuleInput) => void;
  open: boolean;
};

const addRuleFormId = 'add-classification-rule-form';

const defaultValues: ClassificationRuleInput = {
  fieldPath: '',
  level: 'Confidential',
  redaction: 'Mask',
};

export function AddClassificationRuleModal({
  errorMessage,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: AddClassificationRuleModalProps) {
  const t = useTranslations('dashboard.tenantSettings.classification');
  const tStatus = useTranslations('dashboard.status');
  const levelOptions = DATA_CLASS_LEVEL_ORDER.map((level) => ({
    label: tStatus(level),
    value: level,
  }));
  const redactionOptions = REDACTION_IDS.map((id) => ({ label: t(`redaction.${id}`), value: id }));
  const [prevOpen, setPrevOpen] = useState(open);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<ClassificationRuleInput>({
    resolver: zodResolver(ClassificationRuleSchema),
    defaultValues,
    mode: 'onBlur',
  });
  const redaction = useWatch({ control, name: 'redaction' });

  if (open !== prevOpen) {
    setPrevOpen(open);

    if (open) {
      reset(defaultValues);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    reset(defaultValues);
    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      autoFocus={false}
      title={t('modal.title')}
      description={t('modal.description')}
      primaryActionLabel={t('modal.submit')}
      primaryActionType="submit"
      primaryActionForm={addRuleFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form id={addRuleFormId} className="flex flex-col gap-4" onSubmit={handleSubmit(onSubmit)}>
        {errorMessage ? (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
            {errorMessage}
          </p>
        ) : null}

        <Input
          label={t('modal.field')}
          placeholder="user.ssn"
          hint={t('modal.fieldHint')}
          containerClassName="mb-0"
          {...register('fieldPath')}
          error={errors.fieldPath}
          disabled={isSubmitting}
        />

        <Controller
          control={control}
          name="level"
          render={({ field }) => (
            <Select
              label={t('modal.sensitivity')}
              containerClassName="mb-0"
              disabled={isSubmitting}
              error={errors.level?.message}
              options={levelOptions}
              value={field.value}
              onChange={field.onChange}
            />
          )}
        />

        <Controller
          control={control}
          name="redaction"
          render={({ field }) => (
            <Select
              label={t('modal.redaction')}
              containerClassName="mb-0"
              disabled={isSubmitting}
              error={errors.redaction?.message}
              hint={t(`redactionHints.${redaction}`)}
              options={redactionOptions}
              value={field.value}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
