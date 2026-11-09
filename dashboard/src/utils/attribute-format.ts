import type { UserAttributeKind } from '@/types/user-attribute';
import { getActiveLocale } from '@/i18n/active-locale';
import { parseBackendTimestamp } from '@/utils/date';

/**
 * How a stored value reads.
 *
 * Formatting follows what a field *holds*, never the control that captured
 * it: the same amount reads the same whether it was typed into an amount box
 * or a plain number box. Money therefore always carries its cents, a
 * percentage carries only the decimals it has, and every number groups its
 * thousands the way the rest of the dashboard does.
 */

function getFormats(locale: string) {
  return {
    day: new Intl.DateTimeFormat(locale, {
      day: 'numeric',
      month: 'short',
      timeZone: 'UTC',
      year: 'numeric',
    }),
    dayTime: new Intl.DateTimeFormat(locale, {
      day: 'numeric',
      hour: 'numeric',
      hour12: false,
      minute: '2-digit',
      month: 'short',
      year: 'numeric',
    }),
    decimal: new Intl.NumberFormat(locale, { maximumFractionDigits: 4 }),
    money: new Intl.NumberFormat(locale, { maximumFractionDigits: 2, minimumFractionDigits: 2 }),
    percent: new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }),
    wholeNumber: new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }),
  };
}

/** The kinds held as a number, which are the ones a column right-aligns. */
const numericKinds: UserAttributeKind[] = ['decimal', 'money', 'percent', 'whole_number'];

export function isNumericKind(kind: UserAttributeKind) {
  return numericKinds.includes(kind);
}

export function formatAttributeNumber(kind: UserAttributeKind, value: number) {
  switch (kind) {
    case 'money':
      return getFormats(getActiveLocale()).money.format(value);

    case 'percent':
      return `${getFormats(getActiveLocale()).percent.format(value)}%`;

    case 'whole_number':
      return getFormats(getActiveLocale()).wholeNumber.format(value);

    default:
      return getFormats(getActiveLocale()).decimal.format(value);
  }
}

/**
 * A plain `YYYY-MM-DD` carries no time zone, so it is read exactly as it was
 * written rather than shifted into the reader's own.
 */
export function formatAttributeDay(value: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim());

  if (!match) {
    return value;
  }

  const [, year, month, day] = match;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));

  return Number.isNaN(date.getTime()) ? value : getFormats(getActiveLocale()).day.format(date);
}

export function formatAttributeDateTime(value: string) {
  const date = parseBackendTimestamp(value);

  return date ? getFormats(getActiveLocale()).dayTime.format(date) : value;
}
