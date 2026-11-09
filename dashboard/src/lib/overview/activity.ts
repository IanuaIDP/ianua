import type { ActivityDay } from '@/types/activity';

export type CalendarCell = {
  count: number;
  date: Date;
  dateKey: string;
  inRange: boolean;
  isFirstOfMonth: boolean;
  level: number;
};

export function getMonthFormatter(locale: string) {
  return new Intl.DateTimeFormat(locale, { month: 'short' });
}

export function getTooltipDateFormatter(locale: string) {
  return new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  });
}

function parseDateKey(dateKey: string) {
  const [year, month, day] = dateKey.split('-').map(Number);

  return new Date(year, (month ?? 1) - 1, day ?? 1);
}

function formatDateParam(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');

  return `${year}-${month}-${day}`;
}

function computeLevel(count: number, maxCount: number) {
  if (count <= 0 || maxCount <= 0) {
    return 0;
  }

  const ratio = count / maxCount;

  if (ratio > 0.75) {
    return 4;
  }

  if (ratio > 0.5) {
    return 3;
  }

  if (ratio > 0.25) {
    return 2;
  }

  return 1;
}

export function buildCalendarWeeks(
  days: ActivityDay[],
  selectedCategory: string,
): { weeks: CalendarCell[][] } {
  if (days.length === 0) {
    return { weeks: [] };
  }

  const countByDate = new Map<string, number>();
  let maxCount = 0;

  for (const day of days) {
    const categoryCount = day.byCategory.find((item) => item.category === selectedCategory);
    const count = categoryCount?.count ?? 0;

    countByDate.set(day.date, count);
    maxCount = Math.max(maxCount, count);
  }

  const from = parseDateKey(days[0].date);
  const to = parseDateKey(days[days.length - 1].date);
  const startDate = new Date(from);
  startDate.setDate(startDate.getDate() - startDate.getDay());
  const endDate = new Date(to);
  endDate.setDate(endDate.getDate() + (6 - endDate.getDay()));

  const weeks: CalendarCell[][] = [];
  let currentWeek: CalendarCell[] = [];
  const cursor = new Date(startDate);

  while (cursor <= endDate) {
    const dateKey = formatDateParam(cursor);
    const inRange = cursor >= from && cursor <= to;
    const count = countByDate.get(dateKey) ?? 0;

    currentWeek.push({
      count,
      date: new Date(cursor),
      dateKey,
      inRange,
      isFirstOfMonth: cursor.getDate() === 1,
      level: inRange ? computeLevel(count, maxCount) : 0,
    });

    if (currentWeek.length === 7) {
      weeks.push(currentWeek);
      currentWeek = [];
    }

    cursor.setDate(cursor.getDate() + 1);
  }

  return { weeks };
}
