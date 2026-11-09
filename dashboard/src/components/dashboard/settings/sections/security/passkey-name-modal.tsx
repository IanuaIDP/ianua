'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { ReenteredProofFields } from '@/components/dashboard/shared/reentered-proof-fields';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { isStepUpRequiredError } from '@/lib/api';
import type { ReenteredProof } from '@/types/auth';

type PasskeyNameModalProps = {
  defaultValue?: string;
  description: string;
  errorMessage?: string | null;
  /** The refusal behind `errorMessage`, which may ask for a second-factor code. */
  errorCause?: unknown;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (name: string, proof: ReenteredProof) => void;
  open: boolean;
  primaryActionLabel: string;
  /** Asks for the password again, which adding a passkey needs and renaming does not. */
  requireProof?: boolean;
  title: string;
};

/**
 * Shared naming modal for passkeys — used both to name a brand-new passkey
 * right after the browser registration ceremony, and to rename an existing
 * one from the table's actions menu. Callers key this by whatever identifies
 * the current target (ceremony id for add, passkey id for rename) so it
 * remounts with a fresh `name` state instead of carrying over the last value.
 */
export function PasskeyNameModal({
  defaultValue = '',
  description,
  errorCause,
  errorMessage,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  primaryActionLabel,
  requireProof = false,
  title,
}: PasskeyNameModalProps) {
  const t = useTranslations('dashboard.settings.security');
  const [name, setName] = useState(defaultValue);
  const [proof, setProof] = useState<ReenteredProof>({ password: '' });
  const trimmedName = name.trim();
  const isReady = Boolean(trimmedName) && (!requireProof || Boolean(proof.password));

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    onClose();
  }

  function handleConfirm() {
    if (!isReady || isSubmitting) {
      return;
    }

    onSubmit(trimmedName, proof);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      primaryActionLabel={primaryActionLabel}
      onPrimaryAction={handleConfirm}
      isPrimaryActionDisabled={!isReady || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <Input
        label={t('passkeyName.label')}
        value={name}
        onChange={(event) => setName(event.target.value)}
        placeholder={t('passkeyName.placeholder')}
        disabled={isSubmitting}
        containerClassName="mb-0"
        className="bg-cardBg"
        error={errorMessage ?? undefined}
      />

      {requireProof ? (
        <ReenteredProofFields
          disabled={isSubmitting}
          needsCode={isStepUpRequiredError(errorCause)}
          value={proof}
          onChange={setProof}
        />
      ) : null}
    </Modal>
  );
}
