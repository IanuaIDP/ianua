'use client';

import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { GroupSchema, type GroupInput } from '@/schemas/group-schemas';
import type { Group } from '@/types/group';

type GroupFormModalProps = {
  defaultValues?: GroupInput;
  description: string;
  groups: Group[];
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: GroupInput) => void;
  open: boolean;
  primaryActionLabel: string;
  title: string;
};

const emptyFormValues: GroupInput = { name: '', parentId: '' };
const groupFormId = 'group-form';

export function GroupFormModal({
  defaultValues,
  description,
  groups,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  primaryActionLabel,
  title,
}: GroupFormModalProps) {
  const t = useTranslations('dashboard.groups.form');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<GroupInput>({
    resolver: zodResolver(GroupSchema),
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

  function handleFormSubmit(data: GroupInput) {
    onSubmit(data);
  }

  const parentOptions = [
    { label: t('noParent'), value: '' },
    ...groups.map((group) => ({ label: group.name, value: group.id })),
  ];

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      showCloseButton={false}
      primaryActionLabel={primaryActionLabel}
      primaryActionType="submit"
      primaryActionForm={groupFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={groupFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleFormSubmit)}
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

        <Controller
          control={control}
          name="parentId"
          render={({ field }) => (
            <Select
              label={t('parent')}
              hint={t('parentHint')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={parentOptions}
              disabled={isSubmitting}
              error={errors.parentId}
              value={field.value}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
