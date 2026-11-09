'use client';

import { useTranslations } from 'next-intl';

import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Input } from '@/components/ui/Input';
import type { ReenteredProof } from '@/types/auth';

type ReenteredProofFieldsProps = {
  disabled?: boolean;
  /** Set once the API has answered that a second-factor code is needed too. */
  needsCode?: boolean;
  onChange: (proof: ReenteredProof) => void;
  value: ReenteredProof;
};

/** The password typed again, and the code the API may also ask for. */
export function ReenteredProofFields({
  disabled = false,
  needsCode = false,
  onChange,
  value,
}: ReenteredProofFieldsProps) {
  const t = useTranslations('dashboard.settings.security.reenteredProof');

  return (
    <>
      <Input
        label={<span className="text-textGray">{t('password')}</span>}
        type="password"
        autoComplete="current-password"
        value={value.password}
        onChange={(event) => onChange({ ...value, password: event.target.value })}
        disabled={disabled}
        containerClassName="mb-0"
        className="bg-cardBg"
      />

      {needsCode ? (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-medium text-textGray">{t('codePrompt')}</span>
          <VerificationCodeInput
            value={value.code ?? ''}
            onChange={(code) => onChange({ ...value, code })}
          />
        </div>
      ) : null}
    </>
  );
}
