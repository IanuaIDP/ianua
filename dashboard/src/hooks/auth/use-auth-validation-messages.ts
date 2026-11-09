'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import type { AuthValidationMessages } from '@/schemas/auth-schemas';

/** The sign-in, sign-up and password forms' error messages in the current language. */
export function useAuthValidationMessages(): AuthValidationMessages {
  const t = useTranslations('auth.validation');

  return useMemo(
    () => ({
      companyNameRequired: t('companyNameRequired'),
      confirmPasswordRequired: t('confirmPasswordRequired'),
      displayNameRequired: t('displayNameRequired'),
      emailInvalid: t('emailInvalid'),
      fullNameRequired: t('fullNameRequired'),
      passwordRequired: t('passwordRequired'),
      passwordsDoNotMatch: t('passwordsDoNotMatch'),
      termsRequired: t('termsRequired'),
    }),
    [t],
  );
}
