'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { SIGNING_ALGORITHM_OPTIONS } from '@/constants/crypto';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { PlanCryptoMigrationSchema, type PlanCryptoMigrationInput } from '@/schemas/crypto-schemas';
import type { SigningAlgorithm } from '@/types/crypto';

type PlanCryptoMigrationModalProps = {
  excludedAlgorithm?: SigningAlgorithm;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: PlanCryptoMigrationInput) => void;
  open: boolean;
};

const planCryptoMigrationFormId = 'plan-crypto-migration-form';

export function PlanCryptoMigrationModal({
  excludedAlgorithm,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: PlanCryptoMigrationModalProps) {
  const t = useTranslations('dashboard.crypto.migration.planModal');
  const algorithmOptions = SIGNING_ALGORITHM_OPTIONS.filter(
    (option) => option.value !== excludedAlgorithm,
  );
  const defaultAlgorithm = algorithmOptions[0]?.value as SigningAlgorithm | undefined;
  const {
    control,
    formState: { errors },
    handleSubmit,
    reset,
  } = useForm<PlanCryptoMigrationInput>({
    resolver: zodResolver(PlanCryptoMigrationSchema),
    defaultValues: {
      targetAlgorithm: defaultAlgorithm ?? 'ES256',
    },
  });

  useEffect(() => {
    if (!open) {
      reset({ targetAlgorithm: defaultAlgorithm ?? 'ES256' });
    }
  }, [defaultAlgorithm, open, reset]);

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
      primaryActionForm={planCryptoMigrationFormId}
      isPrimaryActionDisabled={isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <form id={planCryptoMigrationFormId} onSubmit={handleSubmit(onSubmit)}>
        <Controller
          control={control}
          name="targetAlgorithm"
          render={({ field }) => (
            <Select
              label={t('target')}
              placeholder={t('placeholder')}
              containerClassName="mb-0"
              className="bg-cardBg"
              options={algorithmOptions}
              value={field.value}
              error={errors.targetAlgorithm}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
