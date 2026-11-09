'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';

type CreatePipelineModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (name: string) => void;
  open: boolean;
};

export function CreatePipelineModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
}: CreatePipelineModalProps) {
  const t = useTranslations('dashboard.pipelines.createModal');
  const [wasOpen, setWasOpen] = useState(open);
  const [name, setName] = useState('');

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      setName('');
    }
  }

  const isValid = name.trim().length > 0;

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    setName('');
    onClose();
  }

  function handleSubmit() {
    if (!isValid) {
      return;
    }

    onSubmit(name.trim());
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      primaryActionLabel={t('submit')}
      isPrimaryActionDisabled={!isValid || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onPrimaryAction={handleSubmit}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <Input
        label={t('name')}
        placeholder={t('placeholder')}
        hint={t('hint')}
        containerClassName="mb-0"
        className="bg-cardBg"
        value={name}
        onChange={(event) => setName(event.target.value)}
        disabled={isSubmitting}
      />
    </Modal>
  );
}
