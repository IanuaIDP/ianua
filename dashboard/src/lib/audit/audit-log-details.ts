import type { DetailRow } from '@/types/audit-log';
import { isPlainObject } from '@/utils/object';

export function toDisplayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') {
    return '—';
  }

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  return JSON.stringify(value);
}

export function formatSectionTitle(key: string) {
  const spaced = key.replace(/_/g, ' ');

  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function flattenDetailValue(value: Record<string, unknown>, prefix = ''): DetailRow[] {
  const hasEntityShape = 'kind' in value && 'label' in value;
  const rows: DetailRow[] = [];

  for (const [key, nestedValue] of Object.entries(value)) {
    if (hasEntityShape && key === 'id') {
      continue;
    }

    const path = prefix ? `${prefix}.${key}` : key;

    if (isPlainObject(nestedValue)) {
      rows.push(...flattenDetailValue(nestedValue, path));
    } else {
      rows.push({ key: path, value: toDisplayValue(nestedValue) });
    }
  }

  return rows;
}
