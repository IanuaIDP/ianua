import type { DataClassLevel } from '@/types/classification';

export function toDataClassLevel(value: string | undefined): DataClassLevel {
  const normalized = value?.toLowerCase();

  if (normalized === 'public') {
    return 'Public';
  }

  if (normalized === 'confidential') {
    return 'Confidential';
  }

  if (normalized === 'restricted') {
    return 'Restricted';
  }

  return 'Internal';
}
