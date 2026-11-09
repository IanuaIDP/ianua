'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import {
  RollbackCryptoMigrationSchema,
  type RollbackCryptoMigrationInput,
} from '@/schemas/crypto-schemas';

type RollbackCryptoMigrationModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: RollbackCryptoMigrationInput) => void;
  open: boolean;
};

const rollbackCryptoMigrationFormId = 'rollback-crypto-migration-form';

export function RollbackCryptoMigrationModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: RollbackCryptoMigrationModalProps) {
  const t = useTranslations('dashboard.crypto.migration.rollbackModal');
  const {
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<RollbackCryptoMigrationInput>({
    resolver: zodResolver(RollbackCryptoMigrationSchema),
    defaultValues: {
      reason: '',
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
      primaryActionForm={rollbackCryptoMigrationFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form id={rollbackCryptoMigrationFormId} onSubmit={handleSubmit(onSubmit)}>
        <Input
          label={t('reason')}
          placeholder={t('placeholder')}
          containerClassName="mb-0"
          className="bg-cardBg"
          disabled={isSubmitting}
          error={errors.reason}
          {...register('reason')}
        />
      </form>
    </Modal>
  );
}
