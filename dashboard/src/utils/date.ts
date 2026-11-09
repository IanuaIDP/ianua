import { getActiveLocale } from '@/i18n/active-locale';
import type { AppLocale } from '@/i18n/config';
import { notAvailable } from '@/utils/not-available';

export function parseBackendTimestamp(value?: string | null) {
  if (!value) {
    return null;
  }

  const trimmed = value.trim();
  const match = trimmed.match(
    /^(\d{4}-\d{2}-\d{2})[ T](\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)(?:\s*([+-]\d{2}:\d{2})(?::\d{2})?|\s*Z)?$/,
  );

  if (!match) {
    const fallbackDate = new Date(trimmed);

    return Number.isNaN(fallbackDate.getTime()) ? null : fallbackDate;
  }

  const [, datePart, hour, minute, second, offset] = match;
  const isoString = `${datePart}T${hour.padStart(2, '0')}:${minute}:${second}${offset ?? 'Z'}`;
  const date = new Date(isoString);

  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatBackendDate(value?: string | null, locale: AppLocale = getActiveLocale()) {
  const date = parseBackendTimestamp(value);

  if (!date) {
    return notAvailable(locale);
  }

  return new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  }).format(date);
}

export function formatBackendDateTime(
  value?: string | null,
  locale: AppLocale = getActiveLocale(),
) {
  const date = parseBackendTimestamp(value);

  if (!date) {
    return notAvailable(locale);
  }

  return new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(date);
}

const DATE_TIME_JOINER: Record<AppLocale, string> = { en: ' at ', uk: ' о ' };

export function formatDateTime(date: Date, locale: AppLocale = getActiveLocale()) {
  const formatted = new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    hour: 'numeric',
    hour12: false,
    minute: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(date);

  return formatted.replace(/, (?=[^,]*$)/, DATE_TIME_JOINER[locale]);
}

/** Short unit suffixes of durations: seconds, minutes, hours, days. */
const DURATION_UNITS: Record<AppLocale, { d: string; h: string; m: string; s: string }> = {
  en: { d: 'd', h: 'h', m: 'm', s: 's' },
  uk: { d: ' д', h: ' год', m: ' хв', s: ' с' },
};

export function formatDurationShort(seconds: number, locale: AppLocale = getActiveLocale()) {
  const units = DURATION_UNITS[locale];

  if (seconds <= 0) {
    return `0${units.s}`;
  }

  if (seconds % 86400 === 0) {
    return `${seconds / 86400}${units.d}`;
  }

  if (seconds % 3600 === 0) {
    return `${seconds / 3600}${units.h}`;
  }

  if (seconds % 60 === 0) {
    return `${seconds / 60}${units.m}`;
  }

  return `${seconds}${units.s}`;
}

const EXPIRED: Record<AppLocale, string> = { en: 'Expired', uk: 'Прострочено' };

export function formatCountdown(date: Date, locale: AppLocale = getActiveLocale()) {
  const diffSeconds = Math.floor((date.getTime() - Date.now()) / 1000);
  const units = DURATION_UNITS[locale];

  if (diffSeconds <= 0) {
    return EXPIRED[locale];
  }

  const minute = 60;
  const hour = minute * 60;
  const day = hour * 24;

  if (diffSeconds < minute) {
    return `${diffSeconds}${units.s}`;
  }

  if (diffSeconds < hour) {
    const minutes = Math.floor(diffSeconds / minute);
    const seconds = diffSeconds % minute;
    return `${minutes}${units.m} ${seconds}${units.s}`;
  }

  if (diffSeconds < day) {
    const hours = Math.floor(diffSeconds / hour);
    const minutes = Math.floor((diffSeconds % hour) / minute);
    return `${hours}${units.h} ${minutes}${units.m}`;
  }

  return `${Math.floor(diffSeconds / day)}${units.d}`;
}

/**
 * "5m ago" style age. English keeps its short form; other languages use the
 * browser's own wording through Intl.RelativeTimeFormat.
 */
export function formatRelativeTime(date: Date, locale = 'en') {
  const diffSeconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  const minute = 60;
  const hour = minute * 60;
  const day = hour * 24;
  const month = day * 30;
  const year = day * 365;

  if (locale !== 'en') {
    return formatLocalizedRelativeTime(diffSeconds, locale);
  }

  if (diffSeconds < minute) {
    return 'just now';
  }

  if (diffSeconds < hour) {
    return `${Math.floor(diffSeconds / minute)}m ago`;
  }

  if (diffSeconds < day) {
    return `${Math.floor(diffSeconds / hour)}h ago`;
  }

  if (diffSeconds < month) {
    return `${Math.floor(diffSeconds / day)}d ago`;
  }

  if (diffSeconds < year) {
    return `${Math.floor(diffSeconds / month)}mo ago`;
  }

  return `${Math.floor(diffSeconds / year)}y ago`;
}

function formatLocalizedRelativeTime(diffSeconds: number, locale: string) {
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: 'auto', style: 'short' });
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
  ];

  for (const [unit, seconds] of units) {
    if (diffSeconds >= seconds) {
      return formatter.format(-Math.floor(diffSeconds / seconds), unit);
    }
  }

  return formatter.format(0, 'second');
}
