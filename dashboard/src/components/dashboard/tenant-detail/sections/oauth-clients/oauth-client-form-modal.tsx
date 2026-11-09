'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Textarea } from '@/components/ui/Textarea';
import { OAuthClientFormSchema, type OAuthClientFormInput } from '@/schemas/oauth-client-schemas';

const emptyFormValues: OAuthClientFormInput = { name: '', redirectUris: '' };

type OAuthClientFormModalProps = {
  defaultValues?: OAuthClientFormInput;
  description: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: OAuthClientFormInput) => void;
  open: boolean;
  primaryActionLabel: string;
  title: string;
};

const oauthClientFormId = 'oauth-client-form';

export function OAuthClientFormModal({
  defaultValues,
  description,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  primaryActionLabel,
  title,
}: OAuthClientFormModalProps) {
  const t = useTranslations('dashboard.oauthClients.form');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<OAuthClientFormInput>({
    resolver: zodResolver(OAuthClientFormSchema),
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

  function handleFormSubmit(payload: OAuthClientFormInput) {
    onSubmit(payload);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      primaryActionLabel={primaryActionLabel}
      primaryActionType="submit"
      primaryActionForm={oauthClientFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form
        id={oauthClientFormId}
        className="flex flex-col"
        onSubmit={handleSubmit(handleFormSubmit)}
      >
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          containerClassName="mb-4"
          {...register('name')}
          error={errors.name}
          disabled={isSubmitting}
        />
        <Textarea
          label={t('redirectUrls')}
          placeholder="https://app.example.com/oauth/callback"
          hint={t('redirectUrlsHint')}
          containerClassName="mb-0"
          rows={3}
          {...register('redirectUris')}
          error={errors.redirectUris}
          disabled={isSubmitting}
        />
      </form>
    </Modal>
  );
}
