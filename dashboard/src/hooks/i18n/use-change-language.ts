'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useNotification } from '@/components/ui/notifications';
import { setLocaleCookie } from '@/i18n/actions';
import type { AppLocale } from '@/i18n/config';
import { saveProfileLocale, toProfileSession } from '@/i18n/profile-locale';
import { getApiErrorMessage } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';

/** Waits until the page has re-rendered in `locale`, so text built from `<html lang>` is right. */
async function waitForLanguage(locale: AppLocale) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (document.documentElement.lang === locale) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/**
 * Switches the interface language. The cookie always changes, so the page
 * switches at once; a signed-in user's choice is also saved to their profile.
 */
export function useChangeLanguage() {
  const t = useTranslations('language');
  const { showNotification } = useNotification();
  const queryClient = useQueryClient();
  const [isPending, setIsPending] = useState(false);

  async function changeLanguage(locale: AppLocale) {
    const { access, isAuthenticated, user } = useAuthStore.getState();

    setIsPending(true);

    try {
      await setLocaleCookie(locale);

      // Table text such as dates is worded when the data is fetched, so it is
      // fetched again once the page is in the new language.
      void waitForLanguage(locale).then(() => queryClient.invalidateQueries());

      if (isAuthenticated && user) {
        await saveProfileLocale(toProfileSession({ ...user, access }), locale);
      }
    } catch (error) {
      showNotification({ message: getApiErrorMessage(error, t('saveFailed')), type: 'error' });
    } finally {
      setIsPending(false);
    }
  }

  return { changeLanguage, isPending };
}
