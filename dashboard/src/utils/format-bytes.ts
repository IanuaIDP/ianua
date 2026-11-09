const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** Writes a size in bytes in the largest unit that keeps it above one. */
export function formatBytes(bytes: number) {
  let value = bytes;
  let unit = 0;

  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }

  return `${unit === 0 ? value : value.toFixed(1)} ${UNITS[unit]}`;
}
