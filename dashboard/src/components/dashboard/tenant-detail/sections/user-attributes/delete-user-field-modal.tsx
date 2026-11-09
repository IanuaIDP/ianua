'use client';

import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';

type DeleteUserFieldModalProps = {
  isSubmitting: boolean;
  onClose: () => void;
  onConfirm: () => void;
  open: boolean;
};

/** Confirms permanently deleting an archived field and every value saved in it. */
export function DeleteUserFieldModal({
  isSubmitting,
  onClose,
  onConfirm,
  open,
}: DeleteUserFieldModalProps) {
  const t = useTranslations('dashboard.userFields');

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('deleteModal.title')}
      description={t('deleteModal.description')}
      showCloseButton={false}
      primaryActionLabel={t('deleteModal.submit')}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
      onPrimaryAction={onConfirm}
      onSecondaryAction={onClose}
    >
      <p className="flex items-start gap-2 rounded-lg border border-error bg-error/10 p-2.5 text-[10px] font-medium text-error">
        <span className="material-symbols-rounded text-sm!" aria-hidden="true">
          error
        </span>
        {t('deleteModal.warning')}
      </p>
    </Modal>
  );
}
