export const LOCALES = ['en', 'uk'] as const;

export type AppLocale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: AppLocale = 'en';

// Holds the visitor's language before they sign in, and mirrors the saved
// profile language after they do.
export const LOCALE_COOKIE_NAME = 'ianua-locale';

export const LOCALE_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;

// Each language is shown in its own name, so it stays readable whatever the
// interface language currently is.
export const LOCALE_NATIVE_NAMES: Record<AppLocale, string> = {
  en: 'English',
  uk: 'Українська',
};

// The backend stores BCP 47 regional tags (see GET /locales); the app only
// needs the language part.
const BACKEND_LOCALES: Record<AppLocale, string> = {
  en: 'en-US',
  uk: 'uk-UA',
};

export function isAppLocale(value: unknown): value is AppLocale {
  return typeof value === 'string' && (LOCALES as readonly string[]).includes(value);
}

/** Maps a stored or browser tag such as `uk-UA` to an app language, or `null` when unsupported. */
export function toAppLocale(tag: string | null | undefined): AppLocale | null {
  const language = tag?.trim().split(/[-_]/)[0]?.toLowerCase();

  return isAppLocale(language) ? language : null;
}

/** The tag to send to the backend when saving a user's language. */
export function toBackendLocale(locale: AppLocale): string {
  return BACKEND_LOCALES[locale];
}
