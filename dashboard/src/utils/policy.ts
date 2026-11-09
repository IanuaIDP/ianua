import type {
  PolicyAction,
  PolicyActionKind,
  PolicyCondition,
  PolicyConditionKind,
} from '@/types/policy';

/**
 * Which kind of condition this is.
 *
 * The server sends an externally tagged enum, so a condition carrying a value
 * is an object with one key and the rest are bare strings.
 */
export function getConditionKind(condition: PolicyCondition): PolicyConditionKind {
  return typeof condition === 'string'
    ? condition
    : (Object.keys(condition)[0] as PolicyConditionKind);
}

/** The value a condition carries, or an empty string for the ones that carry none. */
export function getConditionValue(condition: PolicyCondition): string {
  if (typeof condition === 'string') {
    return '';
  }

  const value = Object.values(condition)[0];

  return Array.isArray(value) ? value.join(', ') : String(value);
}

export function getActionKind(action: PolicyAction): PolicyActionKind {
  return typeof action === 'string' ? action : (Object.keys(action)[0] as PolicyActionKind);
}

/** The reason on a Deny, or an empty string for every other action. */
export function getDenyReason(action: PolicyAction): string {
  return typeof action === 'object' && 'Deny' in action ? action.Deny.reason : '';
}

/** The level on a RequireAal, defaulting to the second factor. */
export function getRequiredAal(action: PolicyAction): 'Aal1' | 'Aal2' | 'Aal3' {
  return typeof action === 'object' && 'RequireAal' in action ? action.RequireAal : 'Aal2';
}

/** Reads a condition back as a sentence, for the rule summary and the trace. */
export function describeCondition(condition: PolicyCondition): string {
  const value = getConditionValue(condition);

  switch (getConditionKind(condition)) {
    case 'PathPrefix':
      return `the path starts with ${value}`;
    case 'PathExact':
      return `the path is exactly ${value}`;
    case 'RoleIs':
      return `they hold the ${value} role`;
    case 'RoleIsNot':
      return `they do not hold the ${value} role`;
    case 'CountryIn':
      return `they are in ${value}`;
    case 'CountryNotIn':
      return `they are not in ${value}`;
    case 'MethodIn':
      return `the method is ${value}`;
    case 'RiskAtLeast':
      return `the risk is ${value.toLowerCase()} or above`;
    case 'DeviceKnown':
      return 'the device is trusted';
    case 'DeviceUnknown':
      return 'the device is not trusted';
    case 'SensitiveOperation':
      return 'it is a sensitive action';
    default:
      return 'an unrecognised condition';
  }
}
