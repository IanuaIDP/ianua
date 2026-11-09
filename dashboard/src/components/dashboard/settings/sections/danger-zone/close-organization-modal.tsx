'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { ConfirmationLabel } from '@/utils/confirmation-label';

const REMOVED_ITEM_IDS = [
  'settings',
  'tenants',
  'members',
  'apiKeys',
  'auditLogs',
  'billing',
  'data',
] as const;

type CloseOrganizationModalProps = {
  confirmationValue: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: () => void;
  onConfirmationChange: (value: string) => void;
  open: boolean;
  organizationName: string;
};

export function CloseOrganizationModal({
  confirmationValue,
  isSubmitting = false,
  onClose,
  onConfirm,
  onConfirmationChange,
  open,
  organizationName,
}: CloseOrganizationModalProps) {
  const t = useTranslations('dashboard.settings.dangerZone.close');
  const isConfirmationValid = Boolean(organizationName) && confirmationValue === organizationName;
  const requiredConfirmationText = organizationName || t('theName');

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('modalTitle')}
      description={t('modalDescription')}
      primaryActionLabel={t('title')}
      onPrimaryAction={onConfirm}
      isPrimaryActionDisabled={!isConfirmationValid || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      showCloseButton={false}
      size="lg"
    >
      <div className="rounded-lg border border-error bg-error/10 px-3 py-2.5 text-[10px] font-medium text-error">
        <div className="flex items-center gap-2">
          <span className="material-symbols-rounded text-sm!">error</span>
          <span className="font-bold">{t('warningTitle')}</span>
        </div>
        <ul className="mt-1 list-disc space-y-0.5 pl-7">
          {REMOVED_ITEM_IDS.map((id) => (
            <li key={id}>{t(`removed.${id}`)}</li>
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
