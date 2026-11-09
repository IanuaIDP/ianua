'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { ConfirmationLabel } from '@/utils/confirmation-label';

type DisableScimModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: () => void;
  open: boolean;
};

const confirmationValue = 'DISABLE';

export function DisableScimModal({
  isSubmitting = false,
  onClose,
  onConfirm,
  open,
}: DisableScimModalProps) {
  const t = useTranslations('dashboard.connections.scim.disableModal');
  const [confirmationInput, setConfirmationInput] = useState('');
  const [wasOpen, setWasOpen] = useState(open);

  if (open !== wasOpen) {
    setWasOpen(open);

    if (!open) {
      setConfirmationInput('');
    }
  }

  function handleClose() {
    setConfirmationInput('');
    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      onPrimaryAction={onConfirm}
      isPrimaryActionDisabled={confirmationInput !== confirmationValue || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
    >
      <div>
        <p className="mb-3 text-xs text-textGray">
          <ConfirmationLabel value={confirmationValue} />
        </p>
        <Input
          value={confirmationInput}
          onChange={(event) => setConfirmationInput(event.target.value)}
          placeholder="DISABLE"
          containerClassName="mb-0"
          className="max-w-48 bg-cardBg"
        />
      </div>
    </Modal>
  );
}
