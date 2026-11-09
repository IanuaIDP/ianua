import type { SelectOption } from '@/types/dashboard';

export const TOOL_METHOD_OPTIONS: SelectOption[] = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'PUT', value: 'PUT' },
  { label: 'PATCH', value: 'PATCH' },
  { label: 'DELETE', value: 'DELETE' },
];

/// Ids of the action classes; the visible names are `dashboard.tools.actionClasses.<id>`.
export const TOOL_ACTION_CLASSES = [
  'read',
  'write',
  'delete',
  'configure',
  'communicate',
  'financial',
  'admin',
] as const;
