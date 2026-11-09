'use client';

import { useCallback } from 'react';
import { useLocale, useTranslations } from 'next-intl';

import type { PasswordPolicy } from '@/types/auth-config';
import { getPasswordRequirementsHint, type PasswordHintTranslation } from '@/utils/password-policy';

/** Returns a function that words a password policy in the current language. */
export function usePasswordRequirementsHint() {
  const locale = useLocale();
  const t = useTranslations('auth.passwordPolicy');

  return useCallback(
    (policy: PasswordPolicy) =>
      getPasswordRequirementsHint(policy, {
        locale,
        t: t as unknown as PasswordHintTranslation['t'],
      }),
    [locale, t],
  );
}
