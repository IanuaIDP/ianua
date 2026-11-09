import { LOCALE_COOKIE_NAME, toAppLocale } from '@/i18n/config';
import type { AppLocale } from '@/i18n/config';

/** The language currently stored in the cookie, read in the browser. */
export function readLocaleCookie(): AppLocale | null {
  const entry = document.cookie
    .split('; ')
    .find((part) => part.startsWith(`${LOCALE_COOKIE_NAME}=`));

  return toAppLocale(entry ? decodeURIComponent(entry.slice(LOCALE_COOKIE_NAME.length + 1)) : null);
}
