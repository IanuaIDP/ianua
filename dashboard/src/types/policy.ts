import type { AssuranceLevel } from '@/types/auth-config';

export type PolicyStatus = 'Draft' | 'Review' | 'Active' | 'Archived';

export type RiskThreshold = 'Low' | 'Medium' | 'High' | 'Critical';

// The server states these as an externally tagged enum, so a condition is an
// object with exactly one key naming its kind. The unit ones are bare strings.
export type PolicyCondition =
  | { PathPrefix: string }
  | { PathExact: string }
  | { RoleIs: string }
  | { RoleIsNot: string }
  | { CountryIn: string[] }
  | { CountryNotIn: string[] }
  | { MethodIn: string[] }
  | { RiskAtLeast: RiskThreshold }
  | 'DeviceKnown'
  | 'DeviceUnknown'
  | 'SensitiveOperation';

export type PolicyConditionKind =
  | 'PathPrefix'
  | 'PathExact'
  | 'RoleIs'
  | 'RoleIsNot'
  | 'CountryIn'
  | 'CountryNotIn'
  | 'MethodIn'
  | 'RiskAtLeast'
  | 'DeviceKnown'
  | 'DeviceUnknown'
  | 'SensitiveOperation';

export type PolicyAction =
  | 'Allow'
  | 'RequireDpop'
  | 'AuditOnly'
  | { Deny: { reason: string } }
  | { RequireAal: AssuranceLevel };

export type PolicyActionKind = 'Allow' | 'Deny' | 'RequireAal' | 'RequireDpop' | 'AuditOnly';

export type PolicyRule = {
  action: PolicyAction;
  conditions: PolicyCondition[];
  enabled: boolean;
  name: string;
  priority: number;
};

export type Policy = {
  basedOn: string | null;
  basedOnVersion: number | null;
  defaultAction: PolicyAction;
  editable: boolean;
  rules: PolicyRule[];
  status: PolicyStatus;
  version: number;
};

export type PolicyTransition =
  'submit_for_review' | 'activate' | 'reject' | 'abandon_draft' | 'take_out_of_use';
