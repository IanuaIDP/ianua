'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { CREDENTIAL_ALGORITHM_OPTIONS } from '@/constants/credential';
import { RotateCredentialSchema, type RotateCredentialInput } from '@/schemas/credential-schemas';
import type { Credential } from '@/types/credential';

type RotateCredentialModalProps = {
  credential: Credential | null;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (data: RotateCredentialInput) => void;
};

const rotateCredentialFormId = 'rotate-credential-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

export function RotateCredentialModal({
  credential,
  isSubmitting = false,
  onClose,
  onSubmit,
}: RotateCredentialModalProps) {
  const t = useTranslations('dashboard.credentials.rotateModal');
  const {
    control,
    formState: { errors },
    handleSubmit,
    reset,
  } = useForm<RotateCredentialInput>({
    resolver: zodResolver(RotateCredentialSchema),
    defaultValues: { algorithm: 'ES256', publicKey: '' },
  });

  useEffect(() => {
    if (credential) {
      reset({ algorithm: credential.algorithm, publicKey: '' });
    }
  }, [credential, reset]);

  return (
    <Modal
      open={Boolean(credential)}
      onClose={onClose}
      title={t('title')}
      description={credential ? t('description', { kid: credential.kid }) : undefined}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={rotateCredentialFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={rotateCredentialFormId}
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
      </form>
    </Modal>
  );
}
