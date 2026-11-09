import { DEFAULT_LOCALE, toAppLocale } from '@/i18n/config';
import type { AppLocale } from '@/i18n/config';

/**
 * The language the page is showing right now, read from `<html lang>`.
 *
 * Formatters that run outside React, such as the ones that turn an API
 * response into table text, cannot call a hook. On the server there is no page
 * yet, so they get the default language; a server component that needs
 * another one passes the locale to the formatter itself.
 */
export function getActiveLocale(): AppLocale {
  if (typeof document === 'undefined') {
    return DEFAULT_LOCALE;
  }

  return toAppLocale(document.documentElement.lang) ?? DEFAULT_LOCALE;
}
