export function toDateFilterValue(value: Date | undefined, edge: 'end' | 'start') {
  if (!value) {
    return undefined;
  }

  const date = new Date(
    Date.UTC(
      value.getFullYear(),
      value.getMonth(),
      value.getDate(),
      edge === 'start' ? 0 : 23,
      edge === 'start' ? 0 : 59,
      edge === 'start' ? 0 : 59,
      edge === 'start' ? 0 : 999,
    ),
  );

  if (Number.isNaN(date.getTime())) {
    return undefined;
  }

  return date.toISOString();
}
