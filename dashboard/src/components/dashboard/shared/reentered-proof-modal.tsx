'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { ReenteredProofFields } from '@/components/dashboard/shared/reentered-proof-fields';
import { Modal } from '@/components/ui/modal';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import { getApiErrorMessage, isStepUpRequiredError } from '@/lib/api';
import type { ReenteredProof } from '@/types/auth';

type ReenteredProofModalProps = {
  description: string;
  error?: unknown;
  errorFallback: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (proof: ReenteredProof) => void;
  open: boolean;
};

/**
 * Asks for the password again before a change the API wants proven afresh.
 * Callers key it by whether it is open, so the password never outlives it.
 */
export function ReenteredProofModal({
  description,
  error,
  errorFallback,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: ReenteredProofModalProps) {
  const t = useTranslations('dashboard.settings.security.reenteredProof');
  const [proof, setProof] = useState<ReenteredProof>({ password: '' });
  const needsCode = isStepUpRequiredError(error);
  const isReady =
    Boolean(proof.password) &&
    (!needsCode || (proof.code ?? '').length === VERIFICATION_CODE_LENGTH);

  function handleClose() {
    if (!isSubmitting) {
      onClose();
    }
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={description}
      primaryActionLabel={t('submit')}
      onPrimaryAction={() => onSubmit(proof)}
      isPrimaryActionDisabled={!isReady || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <ReenteredProofFields
        disabled={isSubmitting}
        needsCode={needsCode}
        value={proof}
        onChange={setProof}
      />

      {error ? (
        <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error">
          {getApiErrorMessage(error, errorFallback)}
        </p>
      ) : null}
    </Modal>
  );
}
