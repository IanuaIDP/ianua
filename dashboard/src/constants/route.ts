import type { MultiSelectOption } from '@/components/ui/MultiSelect';
import type { PathRewriteMode, RoutePolicyKind } from '@/types/route';

/// Ids of the policy kinds; the wording is `dashboard.routes.policy.options.<id>`.
export const ROUTE_POLICY_KINDS: RoutePolicyKind[] = [
  'Public',
  'Authenticated',
  'RequireSystemPermission',
  'RequireCustomPermission',
  'RequireScope',
];

export const ROUTE_HTTP_METHOD_OPTIONS: MultiSelectOption[] = [
  { label: 'GET', value: 'Get' },
  { label: 'POST', value: 'Post' },
  { label: 'PUT', value: 'Put' },
  { label: 'PATCH', value: 'Patch' },
  { label: 'DELETE', value: 'Delete' },
  { label: 'HEAD', value: 'Head' },
  { label: 'OPTIONS', value: 'Options' },
];

/// Ids of the ways a path is forwarded; the wording is `dashboard.routes.rewrite.modes.<id>`.
export const PATH_REWRITE_MODES: PathRewriteMode[] = ['keep', 'strip_prefix', 'template'];
