import type { MultiSelectOption } from '@/components/ui/MultiSelect';
import type { SelectOption } from '@/types/dashboard';

function toSnakeCase(pascalCase: string) {
  const words = pascalCase.match(/[A-Z][a-z0-9]*/g) ?? [pascalCase];
  return words.map((word) => word.toLowerCase()).join('_');
}

function getDomainActionStrings(permissionSet: Set<string>): string[] {
  return Array.from(permissionSet)
    .sort()
    .map((permission) => {
      const [resource, action] = permission.split(':');

      if (!resource || !action) {
        return null;
      }

      return `${toSnakeCase(resource)}:${action.toLowerCase()}`;
    })
    .filter((domainAction): domainAction is string => domainAction !== null);
}

/// `labelFor` words a `domain:action` pair in the current language.
export function buildDelegationCapabilityOptions(
  permissionSet: Set<string>,
  labelFor: (domainAction: string) => string,
): MultiSelectOption[] {
  return getDomainActionStrings(permissionSet).map((domainAction) => ({
    description: domainAction,
    label: labelFor(domainAction),
    value: `http|${domainAction}`,
  }));
}

export function buildAuthorizationCapabilityOptions(
  permissionSet: Set<string>,
  labelFor: (domainAction: string) => string,
): SelectOption[] {
  return getDomainActionStrings(permissionSet).map((domainAction) => ({
    label: labelFor(domainAction),
    value: domainAction,
  }));
}

/// Seconds offered as a delegation's lifetime; the wording is `dashboard.delegations.ttl.<seconds>`.
export const DELEGATION_TTL_SECONDS = ['600', '900', '1800', '3600'];

/// Delegation depths offered; the wording is `dashboard.delegations.depth.<depth>`.
export const DELEGATION_DEPTHS = ['0', '1', '2'];

/// Seconds offered as the request-limit window; the wording is `dashboard.delegations.window.<seconds>`.
export const DELEGATION_BUDGET_WINDOW_SECONDS = ['900', '3600', '86400'];

/// Access levels on a resource; the wording is `dashboard.delegations.relations.<relation>`.
export const DELEGATION_RESOURCE_RELATIONS = ['reader', 'writer', 'approver', 'owner'];

/// How an authorization check is phrased; the wording is `dashboard.delegations.check.modes.<mode>`.
export const AUTHORIZE_CHECK_MODES = ['capability', 'request'];

/// HTTP methods of a request-path check; `Any` is worded in `dashboard.delegations.check.anyMethod`.
export const AUTHORIZE_CHECK_METHODS = [
  'Get',
  'Post',
  'Put',
  'Patch',
  'Delete',
  'Head',
  'Options',
  'Any',
];

/// A named bundle of guardrails, so the common case is one click instead of
/// six fields. Every value here is one an operator could set by hand in
/// Advanced — the preset chooses, it does not hide.
export type DelegationPresetId = 'tight' | 'standard' | 'broad';

export type DelegationPreset = {
  id: DelegationPresetId;
  maxDepth: string;
  requestLimit: string;
  requestLimitWindowSeconds: string;
  requiresApproval: boolean;
  senderConstrained: boolean;
  ttlSeconds: string;
};

export const DELEGATION_PRESETS: DelegationPreset[] = [
  {
    id: 'tight',
    maxDepth: '0',
    requestLimit: '100',
    requestLimitWindowSeconds: '3600',
    requiresApproval: true,
    senderConstrained: true,
    ttlSeconds: '900',
  },
  {
    id: 'standard',
    maxDepth: '0',
    requestLimit: '500',
    requestLimitWindowSeconds: '3600',
    requiresApproval: false,
    senderConstrained: true,
    ttlSeconds: '3600',
  },
  {
    id: 'broad',
    maxDepth: '1',
    requestLimit: '',
    requestLimitWindowSeconds: '3600',
    requiresApproval: false,
    senderConstrained: false,
    ttlSeconds: '3600',
  },
];

export function findDelegationPreset(id: DelegationPresetId): DelegationPreset {
  return DELEGATION_PRESETS.find((preset) => preset.id === id) ?? DELEGATION_PRESETS[1];
}

/// Builds MCP tool options from the tenant's registered tools.
///
/// The registry is the ceiling the backend enforces, so offering anything else
/// would be offering a grant that is going to be refused.
export function buildToolCapabilityOptions(
  tools: { description: string; method: string; name: string; path: string }[],
): MultiSelectOption[] {
  return tools.map((tool) => ({
    description: tool.description || `${tool.method} ${tool.path}`,
    label: tool.name,
    value: `tool|${tool.name}`,
  }));
}
