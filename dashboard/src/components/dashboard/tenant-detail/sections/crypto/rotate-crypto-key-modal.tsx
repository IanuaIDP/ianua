'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { SIGNING_ALGORITHM_OPTIONS } from '@/constants/crypto';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { RotateCryptoKeySchema, type RotateCryptoKeyInput } from '@/schemas/crypto-schemas';

type RotateCryptoKeyModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: RotateCryptoKeyInput) => void;
  open: boolean;
};

const rotateCryptoKeyFormId = 'rotate-crypto-key-form';

export function RotateCryptoKeyModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: RotateCryptoKeyModalProps) {
  const t = useTranslations('dashboard.crypto.keys.rotateModal');
  const {
    control,
    formState: { errors },
    handleSubmit,
    reset,
  } = useForm<RotateCryptoKeyInput>({
    resolver: zodResolver(RotateCryptoKeySchema),
    defaultValues: {
      algorithm: 'ES256',
    },
  });

  useEffect(() => {
    if (!open) {
      reset();
    }
  }, [open, reset]);

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
      title={t('title')}
      description={t('description')}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={rotateCryptoKeyFormId}
      isPrimaryActionDisabled={isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form id={rotateCryptoKeyFormId} onSubmit={handleSubmit(onSubmit)}>
        <Controller
          control={control}
          name="algorithm"
          render={({ field }) => (
            <Select
              label={t('algorithm')}
              placeholder={t('placeholder')}
              containerClassName="mb-0"
              className="bg-cardBg"
              options={SIGNING_ALGORITHM_OPTIONS}
              value={field.value}
              error={errors.algorithm}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
