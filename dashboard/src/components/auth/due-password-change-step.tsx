'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { SetPasswordForm } from '@/components/auth/set-password-form';
import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import {
  completeDuePasswordChange,
  type DuePasswordChangeProof,
  type LoginResult,
  type TenantAuthContext,
} from '@/lib/api/services/auth';
import { getDeviceFingerprint } from '@/lib/auth/device';

type DuePasswordChangeStepProps = {
  changeToken: string | null;
  context: TenantAuthContext;
  email: string;
  onBack: () => void;
  onContinue: (result: LoginResult) => void;
  proof: DuePasswordChangeProof;
};

/**
 * The step a sign-in passes through when its password was set by an
 * administrator or has expired: a new password, then the sign-in carries on.
 */
export function DuePasswordChangeStep({
  changeToken,
  context,
  email,
  onBack,
  onContinue,
  proof,
}: DuePasswordChangeStepProps) {
  const t = useTranslations('auth.duePasswordChange');
  const [code, setCode] = useState('');
  const needsCode = proof === 'own_factor';

  if (!changeToken) {
    return (
      <AuthCard
        title={t('checkEmailTitle')}
        subtitle={t('checkEmailSubtitle')}
        onBackToLogin={onBack}
      >
        {null}
      </AuthCard>
    );
  }

  async function submit(newPassword: string) {
    if (!changeToken) {
      return;
    }

    if (needsCode && code.length !== VERIFICATION_CODE_LENGTH) {
      throw new Error(t('codeRequired'));
    }

    const fingerprintHash = await getDeviceFingerprint();

    onContinue(
      await completeDuePasswordChange(context, email, {
        changeToken,
        code: needsCode ? code : undefined,
        fingerprintHash,
        newPassword,
      }),
    );
  }

  return (
    <AuthCard title={t('title')} subtitle={t('subtitle')} onBackToLogin={onBack}>
      <SetPasswordForm
        onSubmit={submit}
        requireTermsAgreement={false}
        submitErrorFallback={t('failed')}
      >
        {needsCode ? (
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium text-textGray">{t('codePrompt')}</span>
            <VerificationCodeInput value={code} onChange={setCode} />
          </div>
        ) : null}
      </SetPasswordForm>
    </AuthCard>
  );
}
