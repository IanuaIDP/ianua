'use server';

import { cookies } from 'next/headers';

import { LOCALE_COOKIE_MAX_AGE_SECONDS, LOCALE_COOKIE_NAME, isAppLocale } from '@/i18n/config';

/** Stores the chosen language in the cookie; the page re-renders in it. */
export async function setLocaleCookie(locale: string) {
  if (!isAppLocale(locale)) {
    throw new Error(`Unsupported language: ${locale}`);
  }

  const cookieStore = await cookies();

  cookieStore.set(LOCALE_COOKIE_NAME, locale, {
    maxAge: LOCALE_COOKIE_MAX_AGE_SECONDS,
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
}
