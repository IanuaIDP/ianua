'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { ConfirmationLabel } from '@/utils/confirmation-label';
import type { Connection } from '@/types/connection';

type DeleteConnectionModalProps = {
  connection: Connection | null;
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: (connection: Connection) => void;
};

const confirmationValue = 'DELETE';

export function DeleteConnectionModal({
  connection,
  isSubmitting = false,
  onClose,
  onConfirm,
}: DeleteConnectionModalProps) {
  const t = useTranslations('dashboard.connections.deleteModal');
  const [confirmationInput, setConfirmationInput] = useState('');
  const open = Boolean(connection);
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
      onPrimaryAction={() => {
        if (connection) {
          onConfirm(connection);
        }
      }}
      isPrimaryActionDisabled={confirmationInput !== confirmationValue || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
    >
      {connection?.isJitProvisioningEnabled ? (
        <div className="flex items-start gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium text-orange">
          <span className="material-symbols-rounded text-sm! shrink-0">warning</span>
          {t('scimWarning')}
        </div>
      ) : null}

      <div>
        <p className="mb-3 text-xs text-textGray">
          <ConfirmationLabel value={confirmationValue} />
        </p>
        <Input
          value={confirmationInput}
          onChange={(event) => setConfirmationInput(event.target.value)}
          placeholder="DELETE"
          containerClassName="mb-0"
          className="max-w-48 bg-cardBg"
        />
      </div>
    </Modal>
  );
}
