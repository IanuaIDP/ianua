'use client';

import { useTranslations } from 'next-intl';

type RecoveryCodesProps = {
  codes: string[];
};

/** A new second factor's recovery codes, shown once. */
export function RecoveryCodes({ codes }: RecoveryCodesProps) {
  const t = useTranslations('auth.mfa');

  return (
    <div className="space-y-3">
      <p className="text-sm text-textGray">{t('recoveryCodesNote')}</p>
      <ul className="grid grid-cols-2 gap-2 rounded-lg bg-hoverBg p-3 font-mono text-sm text-white">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
    </div>
  );
}
