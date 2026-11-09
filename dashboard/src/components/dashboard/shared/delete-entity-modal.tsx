'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { ConfirmationLabel } from '@/utils/confirmation-label';

type DeleteEntityModalProps = {
  confirmationValue: string;
  description: string;
  entityName: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: () => void;
  onConfirmationChange: (value: string) => void;
  open: boolean;
  primaryActionLabel: string;
  removeItems: string[];
  title: string;
  warningTitle: string;
};

export function DeleteEntityModal({
  confirmationValue,
  description,
  entityName,
  isSubmitting = false,
  onClose,
  onConfirm,
  onConfirmationChange,
  open,
  primaryActionLabel,
  removeItems,
  title,
  warningTitle,
}: DeleteEntityModalProps) {
  const t = useTranslations('dashboard.confirm');
  const isConfirmationValid = Boolean(entityName) && confirmationValue === entityName;
  const requiredConfirmationText = entityName || t('theName');

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      primaryActionLabel={primaryActionLabel}
      onPrimaryAction={onConfirm}
      isPrimaryActionDisabled={!isConfirmationValid || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      showCloseButton={false}
      size="lg"
    >
      <div className="rounded-lg border border-error bg-error/10 px-3 py-2.5 text-[10px] font-medium text-error">
        <div className="flex items-center gap-2">
          <span className="material-symbols-rounded text-sm!">error</span>
          <span className="font-bold">{warningTitle}</span>
        </div>
        <ul className="mt-1 grid grid-cols-1 gap-x-4 list-disc space-y-0.5 pl-7 sm:grid-cols-2">
          {removeItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>

      <Input
        label={
          <span className="text-textGray">
            <ConfirmationLabel value={requiredConfirmationText} />
          </span>
        }
        value={confirmationValue}
        onChange={(event) => onConfirmationChange(event.target.value)}
        placeholder={requiredConfirmationText}
        containerClassName="mb-0"
        className="max-w-52 bg-cardBg"
      />
    </Modal>
  );
}
