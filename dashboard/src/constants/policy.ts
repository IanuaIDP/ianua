import type { PolicyAction, PolicyCondition, PolicyConditionKind } from '@/types/policy';

export const CONDITION_IDS: PolicyConditionKind[] = [
  'PathPrefix',
  'PathExact',
  'RoleIs',
  'RoleIsNot',
  'CountryIn',
  'CountryNotIn',
  'MethodIn',
  'RiskAtLeast',
  'DeviceKnown',
  'DeviceUnknown',
  'SensitiveOperation',
];

export const ACTION_IDS = ['Allow', 'Deny', 'RequireAal', 'RequireDpop', 'AuditOnly'] as const;

export const RISK_THRESHOLD_IDS = ['Low', 'Medium', 'High', 'Critical'] as const;

export const REQUIRED_AAL_IDS = ['Aal1', 'Aal2', 'Aal3'] as const;

/** The conditions that carry no value, so the editor hides the value box. */
export const VALUELESS_CONDITIONS: PolicyConditionKind[] = [
  'DeviceKnown',
  'DeviceUnknown',
  'SensitiveOperation',
];

/** The conditions whose value is a comma-separated list rather than one string. */
export const LIST_CONDITIONS: PolicyConditionKind[] = ['CountryIn', 'CountryNotIn', 'MethodIn'];

/** Builds a condition of the chosen kind from what the editor has typed. */
export function buildCondition(kind: PolicyConditionKind, value: string): PolicyCondition {
  if (VALUELESS_CONDITIONS.includes(kind)) {
    return kind as PolicyCondition;
  }

  if (LIST_CONDITIONS.includes(kind)) {
    const items = value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);

    return { [kind]: items } as PolicyCondition;
  }

  return { [kind]: value } as PolicyCondition;
}

/** Builds an action from the chosen kind and whichever extra field it needs. */
export function buildAction(kind: string, reason: string, aal: string): PolicyAction {
  if (kind === 'Deny') {
    return { Deny: { reason: reason || 'not allowed by policy' } };
  }

  if (kind === 'RequireAal') {
    return { RequireAal: aal as 'Aal1' | 'Aal2' | 'Aal3' };
  }

  return kind as PolicyAction;
}
