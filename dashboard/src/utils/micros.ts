const MICROS_PER_UNIT = 1_000_000;

/** Reads a typed amount as millionths of a unit, or `null` when it is no amount. */
export function microsFromAmount(text: string): number | null {
  const trimmed = text.trim();

  if (!/^\d+(\.\d{1,6})?$/.test(trimmed)) {
    return null;
  }

  return Math.round(Number(trimmed) * MICROS_PER_UNIT);
}

/** Writes millionths of a unit as the amount a person reads. */
export function amountFromMicros(micros: number): string {
  return String(micros / MICROS_PER_UNIT);
}
