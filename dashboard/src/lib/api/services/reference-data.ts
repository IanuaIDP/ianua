import { getActiveLocale } from '@/i18n/active-locale';
import { getList } from '@/lib/api/crud';
import type { SelectOption } from '@/types/dashboard';

function getLocaleDisplayNames() {
  try {
    const locale = getActiveLocale();

    return new Intl.DisplayNames([locale], {
      type: 'language',
      style: locale === 'en' ? 'long' : 'short',
    });
  } catch {
    return null;
  }
}

function formatTimezoneLabel(timezone: string) {
  return timezone.replace(/_/g, ' ');
}

function formatLocaleLabel(locale: string) {
  try {
    return getLocaleDisplayNames()?.of(locale) ?? locale;
  } catch {
    return locale;
  }
}

export async function getTimezones(): Promise<SelectOption[]> {
  const timezones = await getList<string[]>('/timezones');

  return timezones.map((timezone) => ({
    label: formatTimezoneLabel(timezone),
    value: timezone,
  }));
}

export async function getLocales(): Promise<SelectOption[]> {
  const locales = await getList<string[]>('/locales');

  return locales.map((locale) => ({
    label: formatLocaleLabel(locale),
    value: locale,
  }));
}
