import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import type {
  Policy,
  PolicyAction,
  PolicyCondition,
  PolicyRule,
  PolicyStatus,
  PolicyTransition,
} from '@/types/policy';

type PolicyRuleResponse = {
  action: PolicyAction;
  conditions: PolicyCondition[];
  enabled: boolean;
  name: string;
  priority: number;
};

type PolicyApiResponse = {
  based_on?: string | null;
  based_on_version?: number | null;
  default_action: PolicyAction;
  editable: boolean;
  rules: PolicyRuleResponse[];
  status: PolicyStatus;
  version: number;
};

type NewPolicyRuleRequest = {
  action: PolicyAction;
  conditions: PolicyCondition[];
  name: string;
  priority: number;
};

type StartPolicyDraftRequest =
  { default_action: PolicyAction; from: 'blank' } | { from: 'next_version' };

function getPolicyEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/authorization/policy`;
}

function toPolicy(response: PolicyApiResponse): Policy {
  return {
    basedOn: response.based_on ?? null,
    basedOnVersion: response.based_on_version ?? null,
    defaultAction: response.default_action,
    editable: response.editable,
    rules: response.rules,
    status: response.status,
    version: response.version,
  };
}

export async function getPolicy(orgSlug: string, tenantSlug: string): Promise<Policy> {
  const response = await getList<PolicyApiResponse>(getPolicyEndpoint(orgSlug, tenantSlug));

  return toPolicy(response);
}

function isSameRuleContent(left: PolicyRule, right: PolicyRule) {
  return (
    JSON.stringify([left.action, left.conditions, left.priority]) ===
    JSON.stringify([right.action, right.conditions, right.priority])
  );
}

function toNewRuleRequest(rule: PolicyRule): NewPolicyRuleRequest {
  return {
    action: rule.action,
    conditions: rule.conditions,
    name: rule.name,
    priority: rule.priority,
  };
}

/**
 * Saves the edited draft. The API changes rules one at a time, so the edit is
 * compared with the saved version and sent as the changes it adds up to. A
 * renamed rule reads as one removed and one added.
 */
export async function updatePolicy(
  orgSlug: string,
  tenantSlug: string,
  saved: Policy,
  edited: { defaultAction: PolicyAction; rules: PolicyRule[] },
): Promise<void> {
  const endpoint = getPolicyEndpoint(orgSlug, tenantSlug);
  const ruleEndpoint = (name: string) => `${endpoint}/rules/${encodeURIComponent(name)}`;
  const savedByName = new Map(saved.rules.map((rule) => [rule.name, rule]));
  const editedNames = new Set(edited.rules.map((rule) => rule.name));

  for (const rule of saved.rules) {
    if (!editedNames.has(rule.name)) {
      await apiClient.delete(ruleEndpoint(rule.name));
    }
  }

  for (const rule of edited.rules) {
    const previous = savedByName.get(rule.name);

    if (!previous) {
      await apiClient.post(`${endpoint}/rules`, toNewRuleRequest(rule));
    } else if (!isSameRuleContent(previous, rule)) {
      await apiClient.put(ruleEndpoint(rule.name), toNewRuleRequest(rule));
    }

    if (rule.enabled !== (previous?.enabled ?? true)) {
      await apiClient.put(`${ruleEndpoint(rule.name)}/enabled`, { enabled: rule.enabled });
    }
  }

  if (JSON.stringify(edited.defaultAction) !== JSON.stringify(saved.defaultAction)) {
    await apiClient.put(`${endpoint}/default-action`, { default_action: edited.defaultAction });
  }
}

/** Opens a draft beside the live version, or an empty one when nothing is live yet. */
export async function startPolicyDraft(
  orgSlug: string,
  tenantSlug: string,
  defaultAction?: PolicyAction,
): Promise<Policy> {
  const request: StartPolicyDraftRequest = defaultAction
    ? { default_action: defaultAction, from: 'blank' }
    : { from: 'next_version' };
  const response = await apiClient.post<PolicyApiResponse>(
    `${getPolicyEndpoint(orgSlug, tenantSlug)}/draft`,
    request,
  );

  return toPolicy(response.data);
}

export async function changePolicyStatus(
  orgSlug: string,
  tenantSlug: string,
  transition: PolicyTransition,
): Promise<Policy> {
  const response = await apiClient.post<PolicyApiResponse>(
    `${getPolicyEndpoint(orgSlug, tenantSlug)}/status`,
    transition,
  );

  return toPolicy(response.data);
}
