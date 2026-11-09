'use client';

import { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { useTranslations } from 'next-intl';

import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Modal } from '@/components/ui/modal';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';

type MfaSetupModalProps = {
  isConfirming: boolean;
  mfaSetup: { otpauth_uri: string } | null;
  onClose: () => void;
  onConfirm: (code: string) => void;
};

export function MfaSetupModal({ isConfirming, mfaSetup, onClose, onConfirm }: MfaSetupModalProps) {
  const t = useTranslations('dashboard.settings.security');
  const [verificationCode, setVerificationCode] = useState('');

  function handleClose() {
    setVerificationCode('');
    onClose();
  }

  return (
    <Modal
      open={Boolean(mfaSetup)}
      onClose={handleClose}
      title={t('mfaSetup.title')}
      description={t('mfaSetup.description')}
      primaryActionLabel={t('mfaSetup.submit')}
      onPrimaryAction={() => onConfirm(verificationCode)}
      isPrimaryActionDisabled={verificationCode.length !== VERIFICATION_CODE_LENGTH || isConfirming}
      isPrimaryActionLoading={isConfirming}
      onSecondaryAction={handleClose}
      showCloseButton={false}
    >
      <div className="flex min-h-34 items-center justify-center rounded-[10px] bg-white p-3">
        {mfaSetup?.otpauth_uri ? (
          <QRCodeSVG
            value={mfaSetup.otpauth_uri}
            size={112}
            bgColor="transparent"
            fgColor="#1d1d1d"
            level="M"
            title={t('mfaSetup.qrTitle')}
          />
        ) : (
          <p className="px-4 text-center text-xs font-medium text-appBg">
            {t('mfaSetup.missingUri')}
          </p>
        )}
      </div>

      <VerificationCodeInput value={verificationCode} onChange={setVerificationCode} />
    </Modal>
  );
}
