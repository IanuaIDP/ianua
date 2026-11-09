import type { DataClassLevel, RedactionStrategy } from '@/types/classification';

// The names and explanations of these are in messages/<language>.json under
// dashboard.tenantSettings.classification.
export const REDACTION_IDS: RedactionStrategy[] = ['Remove', 'Mask', 'Hash'];

export const DATA_CLASS_LEVEL_ORDER: DataClassLevel[] = [
  'Public',
  'Internal',
  'Confidential',
  'Restricted',
];
