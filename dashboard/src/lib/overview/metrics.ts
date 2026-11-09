import { cn } from '@/utils/cn';
import type { AuthenticationMetrics, ChangeTone, OverviewMetricItem } from '@/types/overview';
import { formatBackendDateTime } from '@/utils/date';
import { getActiveLocale } from '@/i18n/active-locale';
import { notAvailable } from '@/utils/not-available';

const fallbackChartPoints: [number, number, number, number, number] = [0, 0, 0, 0, 0];
const monthlyWindowDays = 30;
const fivePointSamplePositions = [0, 0.25, 0.5, 0.75, 1];
const threePointSamplePositions = [0, 0.5, 1];

export type MetricsWindow = 'daily' | 'monthly';

export function formatTrend(changePct?: number | null) {
  if (changePct === null || changePct === undefined) {
    return notAvailable();
  }

  const roundedValue = Math.round(changePct);
  return `${roundedValue > 0 ? '+' : ''}${roundedValue}%`;
}

export function getTrendTone(direction?: string | null, changePct?: number | null): ChangeTone {
  const normalizedDirection = direction?.toLowerCase();

  if (normalizedDirection === 'down') {
    return 'down';
  }

  if (normalizedDirection === 'up') {
    return 'up';
  }

  if (normalizedDirection === 'flat') {
    return 'flat';
  }

  if (changePct === undefined || changePct === null || changePct === 0) {
    return 'flat';
  }

  return changePct < 0 ? 'down' : 'up';
}

export function getFailedAttemptsTone(value?: number | null): ChangeTone {
  if (value === undefined || value === null || value === 0) {
    return 'flat';
  }

  return value > 0 ? 'down' : 'up';
}

export function formatNumber(value?: number | null) {
  return value === null || value === undefined
    ? notAvailable()
    : new Intl.NumberFormat(getActiveLocale()).format(value);
}

export function formatPercent(value?: number | null) {
  if (value === null || value === undefined) {
    return notAvailable();
  }

  return `${Math.round(value)}%`;
}

export function formatLatency(valueMs?: number | null) {
  if (valueMs === null || valueMs === undefined) {
    return notAvailable();
  }

  const isUk = getActiveLocale() === 'uk';

  if (valueMs >= 1000) {
    return `${Math.round(valueMs / 1000)}${isUk ? ' с' : 's'}`;
  }

  return `${Math.round(valueMs)}${isUk ? ' мс' : 'ms'}`;
}

export function formatLastLoginDate(value?: string | null) {
  return formatBackendDateTime(value);
}

function formatTimestampParam(value: Date) {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, '0');
  const day = String(value.getDate()).padStart(2, '0');
  const hours = String(value.getHours()).padStart(2, '0');
  const minutes = String(value.getMinutes()).padStart(2, '0');
  const seconds = String(value.getSeconds()).padStart(2, '0');
  const offsetMinutes = -value.getTimezoneOffset();
  const offsetSign = offsetMinutes >= 0 ? '+' : '-';
  const offsetHours = String(Math.floor(Math.abs(offsetMinutes) / 60)).padStart(2, '0');
  const offsetRemainderMinutes = String(Math.abs(offsetMinutes) % 60).padStart(2, '0');

  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}${offsetSign}${offsetHours}:${offsetRemainderMinutes}`;
}

export function getMetricsWindowParams(window: MetricsWindow, now = new Date()) {
  const until = new Date(now);
  const since = new Date(until);
  until.setHours(23, 59, 59, 999);

  if (window === 'daily') {
    since.setHours(0, 0, 0, 0);
  } else {
    since.setDate(since.getDate() - (monthlyWindowDays - 1));
    since.setHours(0, 0, 0, 0);
  }

  return {
    since: formatTimestampParam(since),
    until: formatTimestampParam(until),
  };
}

export function getWindowButtonClass(isActive: boolean) {
  return cn(
    'flex-1 whitespace-nowrap rounded-md px-3 py-1.5 text-xs transition sm:flex-none',
    isActive
      ? 'bg-primary/15 font-semibold text-primary'
      : 'font-medium text-textGray hover:text-white',
  );
}

export function toMetricItem(
  label: string,
  value: string,
  trend: { changePct?: number | null; direction?: string | null },
): OverviewMetricItem {
  return {
    change: formatTrend(trend.changePct),
    label,
    tone: getTrendTone(trend.direction, trend.changePct),
    value,
  };
}

function sampleFivePoints(values: number[]): [number, number, number, number, number] {
  if (!values.length) {
    return fallbackChartPoints;
  }

  if (values.length < 5) {
    return fillFlatMiddleIfNeeded(
      [...Array(5 - values.length).fill(values[0]), ...values] as [
        number,
        number,
        number,
        number,
        number,
      ],
      values,
    );
  }

  const indexes = sampleIndexes(values.length, fivePointSamplePositions);
  const sampledValues = indexes.map((index) => values[index]) as [
    number,
    number,
    number,
    number,
    number,
  ];

  return fillFlatMiddleIfNeeded(sampledValues, values);
}

function sampleIndexes(valueCount: number, positions: number[]) {
  const lastIndex = valueCount - 1;

  return positions.map((position) => Math.round(lastIndex * position));
}

function fillFlatMiddleIfNeeded(
  sampledValues: [number, number, number, number, number],
  sourceValues: number[],
): [number, number, number, number, number] {
  if (new Set(sampledValues).size > 1 || new Set(sourceValues).size <= 1) {
    return sampledValues;
  }

  const flatValue = sampledValues[0];
  const alternativeValues = sourceValues.filter((value) => value !== flatValue);

  if (!alternativeValues.length) {
    return sampledValues;
  }

  const middleIndexes = sampleIndexes(alternativeValues.length, threePointSamplePositions);
  const middleValues = middleIndexes.map((index) => alternativeValues[index]) as [
    number,
    number,
    number,
  ];

  return [sampledValues[0], middleValues[0], middleValues[1], middleValues[2], sampledValues[4]];
}

export function getSuccessRatePoints(metrics?: {
  authentication: Pick<AuthenticationMetrics, 'successRateSeries'>;
}): [number, number, number, number, number] {
  const values =
    metrics?.authentication.successRateSeries
      .map((point) => point.successRate)
      .filter((value): value is number => typeof value === 'number') ?? [];

  return sampleFivePoints(values);
}

export function hasSuccessRateSeriesData(metrics?: {
  authentication: Pick<AuthenticationMetrics, 'successRateSeries'>;
}) {
  const values =
    metrics?.authentication.successRateSeries
      .map((point) => point.successRate)
      .filter((value): value is number => typeof value === 'number') ?? [];

  return values.length > 0 && values.some((value) => value !== 0);
}
