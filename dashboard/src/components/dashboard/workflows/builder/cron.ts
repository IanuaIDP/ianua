const FIELD_RANGES = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 6],
];

function isValidPart(part: string, [low, high]: number[]) {
  const [values, step] = part.split('/');

  if (step !== undefined && (!/^\d+$/.test(step) || Number(step) === 0)) {
    return false;
  }

  if (values === '*') {
    return true;
  }

  const [start, end = start] = values.split('-');

  if (!/^\d+$/.test(start) || !/^\d+$/.test(end)) {
    return false;
  }

  return Number(start) >= low && Number(end) <= high && Number(start) <= Number(end);
}

/** The schedule check the API applies, so a bad schedule stays local with a reason. */
export function isValidCron(cron: string) {
  const fields = cron.trim().split(/\s+/);

  return (
    fields.length === 5 &&
    fields.every((field, index) =>
      field.split(',').every((part) => isValidPart(part, FIELD_RANGES[index])),
    )
  );
}

export type CronDescription =
  | { kind: 'custom' }
  | { kind: 'everyHour'; minute: string }
  | { kind: 'everyMinutes'; minutes: string }
  | { kind: 'daily'; time: string }
  | { kind: 'weekdays'; time: string }
  | { day: string; kind: 'weekly'; time: string }
  | { day: string; kind: 'monthly'; time: string };

function toClock(hour: string, minute: string) {
  return `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`;
}

/** The common shapes of a schedule, in a form the screen can say in words. */
export function describeCron(cron: string): CronDescription {
  const [minute, hour, day, month, weekday] = cron.trim().split(/\s+/);
  const isNumber = (value: string) => /^\d+$/.test(value);

  if (month !== '*' || (!isNumber(minute) && !minute?.startsWith('*/'))) {
    return { kind: 'custom' };
  }

  if (minute.startsWith('*/') && hour === '*' && day === '*' && weekday === '*') {
    return { kind: 'everyMinutes', minutes: minute.slice(2) };
  }

  if (isNumber(minute) && hour === '*' && day === '*' && weekday === '*') {
    return { kind: 'everyHour', minute: minute.padStart(2, '0') };
  }

  if (!isNumber(minute) || !isNumber(hour)) {
    return { kind: 'custom' };
  }

  const time = toClock(hour, minute);

  if (day === '*' && weekday === '*') {
    return { kind: 'daily', time };
  }

  if (day === '*' && weekday === '1-5') {
    return { kind: 'weekdays', time };
  }

  if (day === '*' && isNumber(weekday)) {
    return { day: weekday, kind: 'weekly', time };
  }

  if (isNumber(day) && weekday === '*') {
    return { day, kind: 'monthly', time };
  }

  return { kind: 'custom' };
}
