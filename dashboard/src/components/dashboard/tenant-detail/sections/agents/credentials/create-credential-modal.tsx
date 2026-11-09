'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { CREDENTIAL_ALGORITHM_OPTIONS } from '@/constants/credential';
import { useCredentialText } from '@/hooks/dashboard/use-credential-text';
import { CreateCredentialSchema, type CreateCredentialInput } from '@/schemas/credential-schemas';

type CreateCredentialModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CreateCredentialInput) => void;
};

const createCredentialFormId = 'create-credential-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: CreateCredentialInput = {
  algorithm: 'ES256',
  expiresInSeconds: '',
  publicKey: '',
};

export function CreateCredentialModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
}: CreateCredentialModalProps) {
  const t = useTranslations('dashboard.credentials.createModal');
  const { expiryOptions } = useCredentialText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    reset,
  } = useForm<CreateCredentialInput>({
    resolver: zodResolver(CreateCredentialSchema),
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
      primaryActionForm={createCredentialFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={createCredentialFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Controller
          control={control}
          name="algorithm"
          render={({ field }) => (
            <Select
              label={t('algorithm')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              hint={t('algorithmHint')}
              options={CREDENTIAL_ALGORITHM_OPTIONS}
              value={field.value}
              error={errors.algorithm}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          control={control}
          name="publicKey"
          render={({ field }) => (
            <Textarea
              label={t('publicKey')}
              placeholder="-----BEGIN PUBLIC KEY-----"
              hint={t('publicKeyHint')}
              rows={6}
              containerClassName={fieldContainerClassName}
              className="font-mono text-xs"
              value={field.value}
              error={errors.publicKey}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          control={control}
          name="expiresInSeconds"
          render={({ field }) => (
            <Select
              label={t('expiry')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              hint={t('expiryHint')}
              options={expiryOptions}
              value={field.value ?? ''}
              error={errors.expiresInSeconds}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
