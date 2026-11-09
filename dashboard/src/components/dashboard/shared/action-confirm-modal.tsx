'use client';

import type { ReactNode } from 'react';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import type { DashboardActionModalContent } from '@/types/dashboard';
import { cn } from '@/utils/cn';
import { ConfirmationLabel } from '@/utils/confirmation-label';

type ActionConfirmModalProps = {
  confirmationValue: string;
  content: DashboardActionModalContent | null | undefined;
  extraContent?: ReactNode;
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: () => void;
  onConfirmationChange: (value: string) => void;
};

export function ActionConfirmModal({
  confirmationValue,
  content,
  extraContent,
  isSubmitting = false,
  onClose,
  onConfirm,
  onConfirmationChange,
}: ActionConfirmModalProps) {
  const isConfirmationValid =
    !content?.confirmationValue || confirmationValue === content.confirmationValue;

  return (
    <Modal
      open={Boolean(content)}
      onClose={onClose}
      title={content?.title}
      description={content?.description}
      icon={
        content?.warningTone === 'danger' ? (
          <span className="material-symbols-rounded text-3xl! text-error" aria-hidden="true">
            warning
          </span>
        ) : undefined
      }
      primaryActionLabel={content?.primaryActionLabel}
      onPrimaryAction={onConfirm}
      isPrimaryActionDisabled={!isConfirmationValid}
      isPrimaryActionLoading={isSubmitting}
      secondaryActionLabel={content?.secondaryActionLabel}
      showCloseButton={false}
    >
      {content?.warningNote ? (
        <div
          className={cn(
            'flex items-center gap-2 rounded-lg border px-3 py-1 text-[10px] font-medium',
            content.warningTone === 'danger'
              ? 'border-error bg-error/10 text-error'
              : 'border-orange/50 bg-orange/10 text-orange',
          )}
        >
          <span className="material-symbols-rounded text-sm!">
            {content.warningTone === 'danger' ? 'error' : 'warning'}
          </span>
          <span>{content.warningNote}</span>
        </div>
      ) : null}

      {extraContent}

      {content?.confirmationValue ? (
        <div>
          <p className="mb-3 text-xs text-textGray">
            <ConfirmationLabel
              label={content.confirmationLabel}
              value={content.confirmationValue}
            />
          </p>
          <Input
            value={confirmationValue}
            onChange={(event) => onConfirmationChange(event.target.value)}
            placeholder={content.confirmationPlaceholder}
            containerClassName="mb-0"
            className="max-w-48 bg-cardBg"
          />
        </div>
      ) : null}
    </Modal>
  );
}
