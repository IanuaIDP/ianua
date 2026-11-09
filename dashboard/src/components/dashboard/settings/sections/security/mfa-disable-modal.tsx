'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import { ConfirmationLabel } from '@/utils/confirmation-label';

const disableConfirmationValue = 'DISABLE';

type MfaDisableModalProps = {
  isDisabling?: boolean;
  onClose: () => void;
  onConfirm?: (code?: string) => void;
  open: boolean;
  requireCode?: boolean;
};

export function MfaDisableModal({
  isDisabling = false,
  onClose,
  onConfirm,
  open,
  requireCode = false,
}: MfaDisableModalProps) {
  const t = useTranslations('dashboard.settings.security');
  const [confirmationValue, setConfirmationValue] = useState('');
  const [code, setCode] = useState('');
  const isProofReady = !requireCode || code.length === VERIFICATION_CODE_LENGTH;

  function handleClose() {
    if (isDisabling) {
      return;
    }

    setConfirmationValue('');
    setCode('');
    onClose();
  }

  function handleConfirm() {
    if (confirmationValue !== disableConfirmationValue || !isProofReady) {
      return;
    }

    onConfirm?.(requireCode ? code : undefined);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('mfaDisable.title')}
      description={t('mfaDisable.description')}
      icon={<span className="material-symbols-rounded text-4xl! text-orange">warning</span>}
      primaryActionLabel={t('mfaDisable.submit')}
      onPrimaryAction={handleConfirm}
      isPrimaryActionDisabled={
        confirmationValue !== disableConfirmationValue || !isProofReady || isDisabling
      }
      isPrimaryActionLoading={isDisabling}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <div className="rounded-lg border border-orange/50 bg-orange/10 px-3 py-2.5 text-[10px] font-medium text-orange">
        <div className="flex items-center gap-2">
          <span className="material-symbols-rounded text-sm!">encrypted</span>
          <span>{t('mfaDisable.needToKnow')}</span>
        </div>
        <ul className="mt-1 list-disc space-y-0.5 pl-7">
          <li>{t('mfaDisable.risk')}</li>
          <li>{t('mfaDisable.canReEnable')}</li>
        </ul>
      </div>

      <Input
        label={
          <span className="text-textGray">
            <ConfirmationLabel value={disableConfirmationValue} />
          </span>
        }
        value={confirmationValue}
        onChange={(event) => setConfirmationValue(event.target.value)}
        placeholder="DISABLE"
        disabled={isDisabling}
        containerClassName="mb-0"
        className="max-w-48 bg-cardBg"
      />

      {requireCode ? (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-medium text-textGray">{t('mfaDisable.codePrompt')}</span>
          <VerificationCodeInput value={code} onChange={setCode} />
        </div>
      ) : null}
    </Modal>
  );
}
