'use client';

import { useEffect, useRef } from 'react';

import { setLocaleCookie } from '@/i18n/actions';
import { readLocaleCookie } from '@/i18n/client';
import { DEFAULT_LOCALE, toAppLocale } from '@/i18n/config';
import { getProfileLocale } from '@/i18n/profile-locale';
import { useAuthStore } from '@/store/auth-store';

/**
 * Applies the signed-in user's saved language once per session. The profile
 * wins over the cookie, because it follows the user across devices. A user
 * with no saved language, or one the app does not support, keeps the cookie.
 */
export function LocaleSync() {
  const userId = useAuthStore((state) => state.user?.id);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const tenantSlug = useAuthStore((state) => state.user?.tenantSlug);
  const isTenantSession = useAuthStore((state) => state.access === null);
  const syncedUserIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!userId || syncedUserIdRef.current === userId) {
      return;
    }

    syncedUserIdRef.current = userId;
    const cookieAtStart = readLocaleCookie();

    async function syncLanguage() {
      try {
        const savedLocale = toAppLocale(
          await getProfileLocale({ isTenantSession, organizationSlug, tenantSlug }),
        );
        const currentLocale = readLocaleCookie();

        // Someone switched language while the profile was loading: theirs wins.
        if (!savedLocale || currentLocale !== cookieAtStart) {
          return;
        }

        if (savedLocale !== (currentLocale ?? DEFAULT_LOCALE)) {
          await setLocaleCookie(savedLocale);
        }
      } catch {
        // The language is a convenience; keep the current one.
      }
    }

    void syncLanguage();
  }, [isTenantSession, organizationSlug, tenantSlug, userId]);

  return null;
}
