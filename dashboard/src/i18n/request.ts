import { cookies } from 'next/headers';
import { getRequestConfig } from 'next-intl/server';

import { DEFAULT_LOCALE, LOCALE_COOKIE_NAME, toAppLocale } from '@/i18n/config';

// The language comes from a cookie, not the URL, so the two tenant route trees
// keep their paths.
export default getRequestConfig(async () => {
  const cookieStore = await cookies();
  const locale = toAppLocale(cookieStore.get(LOCALE_COOKIE_NAME)?.value) ?? DEFAULT_LOCALE;

  return {
    locale,
    messages: (await import(`../../messages/${locale}.json`)).default,
  };
});
