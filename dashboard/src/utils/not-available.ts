import { getActiveLocale } from '@/i18n/active-locale';
import type { AppLocale } from '@/i18n/config';

const NOT_AVAILABLE: Record<AppLocale, string> = {
  en: 'N/A',
  uk: 'Н/д',
};

/** The text for a value the API did not give, in the current language. */
export function notAvailable(locale: AppLocale = getActiveLocale()) {
  return NOT_AVAILABLE[locale];
}

/** Whether `value` is the text `notAvailable` returns, in any language. */
export function isNotAvailable(value: string) {
  return Object.values(NOT_AVAILABLE).includes(value);
}
