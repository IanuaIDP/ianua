import { apiClient } from '@/lib/api/client';
import { createResource, deleteResource, getList } from '@/lib/api/crud';
import {
  decodeCapabilities,
  parseDelimitedList,
  type DecodedCapabilities,
  type GrantDelegationInput,
} from '@/schemas/delegation-schemas';
import { parseBackendTimestamp } from '@/utils/date';
import type {
  Delegation,
  DelegationDriftMode,
  DelegationOwnerKind,
  DelegationPubSubRights,
  DelegationStatus,
} from '@/types/delegation';

type OwnerResponse = {
  display_name?: string | null;
  id: string;
  kind: string;
};

type BudgetResponse = {
  max_requests: number;
  used_requests?: number | null;
  window_seconds: number;
};

type IntentResponse = {
  mode: string;
  statement: string;
  threshold_basis_points?: number | null;
};

type TopicCapabilityResponse = {
  rights: string;
  topic: string;
};

type ResourceCapabilityResponse = {
  relation: string;
  resource: string;
};

type CapabilitySetResponse = {
  http?: string[] | null;
  mcp_prompts?: string[] | null;
  mcp_resources?: string[] | null;
  messaging?: TopicCapabilityResponse[] | null;
  resources?: ResourceCapabilityResponse[] | null;
  tools?: string[] | null;
};

type DelegationResponse = {
  budget?: BudgetResponse | null;
  delegate: string;
  delegation_id: string;
  delegator: OwnerResponse;
  depth: number;
  expires_at: string;
  granted: CapabilitySetResponse;
  intent?: IntentResponse | null;
  max_depth: number;
  name?: string | null;
  parent?: string | null;
  renewed_at?: string | null;
  requires_approval: boolean;
  resource_scope?: string[] | null;
  apps?: string[] | null;
  revoked: boolean;
  sender_constrained: boolean;
  task?: string | null;
};

function toOwnerKind(value: string): DelegationOwnerKind {
  if (value === 'agent' || value === 'consumer' || value === 'org_user' || value === 'user') {
    return value;
  }

  return 'user';
}

function toDriftMode(value: string): DelegationDriftMode {
  if (value === 'off' || value === 'warn' || value === 'enforce') {
    return value;
  }

  return 'off';
}

function toPubSubRights(value: string): DelegationPubSubRights {
  if (value === 'publish' || value === 'subscribe' || value === 'both') {
    return value;
  }

  return 'both';
}

function toDelegationStatus(response: DelegationResponse): DelegationStatus {
  if (response.revoked) {
    return 'Revoked';
  }

  const expiresAt = parseBackendTimestamp(response.expires_at);

  if (expiresAt && expiresAt.getTime() <= Date.now()) {
    return 'Expired';
  }

  return 'Active';
}

function toDelegation(response: DelegationResponse): Delegation {
  return {
    budget: response.budget
      ? {
          maxRequests: response.budget.max_requests,
          usedRequests: response.budget.used_requests ?? null,
          windowSeconds: response.budget.window_seconds,
        }
      : null,
    delegate: response.delegate,
    delegationId: response.delegation_id,
    delegator: {
      displayName: response.delegator?.display_name ?? null,
      id: response.delegator?.id ?? '',
      kind: toOwnerKind(response.delegator?.kind ?? ''),
    },
    depth: response.depth ?? 0,
    expiresAt: response.expires_at,
    granted: {
      http: response.granted?.http ?? [],
      mcpPrompts: response.granted?.mcp_prompts ?? [],
      mcpResources: response.granted?.mcp_resources ?? [],
      messaging: (response.granted?.messaging ?? []).map((item) => ({
        rights: toPubSubRights(item.rights),
        topic: item.topic,
      })),
      resources: response.granted?.resources ?? [],
      tools: response.granted?.tools ?? [],
    },
    intent: response.intent
      ? {
          mode: toDriftMode(response.intent.mode),
          statement: response.intent.statement,
          thresholdBasisPoints: response.intent.threshold_basis_points ?? null,
        }
      : null,
    maxDepth: response.max_depth,
    name: response.name ?? null,
    parent: response.parent ?? null,
    requiresApproval: Boolean(response.requires_approval),
    resourceScope: response.resource_scope ?? null,
    apps: response.apps ?? null,
    revoked: Boolean(response.revoked),
    senderConstrained: Boolean(response.sender_constrained),
    status: toDelegationStatus(response),
    task: response.task ?? null,
  };
}

function getAgentDelegationsEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/delegations`;
}

function getAgentGrantEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/grant`;
}

function getAgentAuthorizeCheckEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/authorize-check`;
}

export async function getAgentDelegations(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<Delegation[]> {
  const response = await getList<DelegationResponse[]>(
    getAgentDelegationsEndpoint(orgSlug, tenantSlug, agentId),
  );

  return response.map(toDelegation);
}

export async function revokeAgentDelegation(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  delegationId: string,
): Promise<void> {
  await deleteResource<void>(
    getAgentDelegationsEndpoint(orgSlug, tenantSlug, agentId),
    delegationId,
  );
}

function getAgentDelegationResourcesEndpoint(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  delegationId: string,
) {
  return `${getAgentDelegationsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(delegationId)}/resources`;
}

type ResourceCapabilityRequest = {
  relation: string;
  resource: string;
};

export async function grantDelegationResource(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  delegationId: string,
  payload: ResourceCapabilityRequest,
): Promise<Delegation> {
  const response = await apiClient.post<DelegationResponse>(
    getAgentDelegationResourcesEndpoint(orgSlug, tenantSlug, agentId, delegationId),
    payload,
  );

  return toDelegation(response.data);
}

export async function revokeDelegationResource(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  delegationId: string,
  payload: ResourceCapabilityRequest,
): Promise<Delegation> {
  const response = await apiClient.delete<DelegationResponse>(
    getAgentDelegationResourcesEndpoint(orgSlug, tenantSlug, agentId, delegationId),
    { data: payload },
  );

  return toDelegation(response.data);
}

type GrantDelegationRequest = {
  apps?: string[] | null;
  budget?: { max_requests: number; window_seconds: number } | null;
  granted: {
    http: string[];
    tools?: string[];
    messaging: { rights: string; topic: string }[];
    resources: { relation: string; resource: string }[];
  };
  intent?: { mode: string; statement: string; threshold_basis_points?: number | null } | null;
  max_depth: number;
  name: string;
  requires_approval: boolean;
  resource_scope?: string[] | null;
  sender_constrained: boolean;
  task?: string | null;
  ttl_seconds: number;
};

type GrantDelegationResponse = {
  delegation_id: string;
  expires_at: string;
  task_token: string;
};

/// A readable name when the operator did not write one.
///
/// The field used to be required, which made every grant start with naming
/// paperwork. A delegation is identifiable by what it grants, so this says
/// that instead of forcing a title nobody reads.
function defaultDelegationName(capabilities: DecodedCapabilities): string {
  const first = capabilities.tools[0] ?? capabilities.http[0];
  const total =
    capabilities.tools.length + capabilities.http.length + capabilities.resources.length;

  if (!first) {
    return 'Delegation';
  }

  return total > 1 ? `${first} and ${total - 1} more` : first;
}

export async function grantAgentDelegation(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  input: GrantDelegationInput,
): Promise<{ delegationId: string; expiresAt: string; taskToken: string }> {
  const purpose = input.purpose?.trim();
  const task = input.task?.trim();
  const requestLimit = input.requestLimit?.trim();
  const allowedPaths = parseDelimitedList(input.allowedPaths);
  const capabilities = decodeCapabilities(input.capabilities);

  const body: GrantDelegationRequest = {
    apps: input.apps.length ? input.apps : null,
    budget: requestLimit
      ? {
          max_requests: Number(requestLimit),
          window_seconds: Number(input.requestLimitWindowSeconds),
        }
      : null,
    granted: capabilities,
    intent: purpose
      ? {
          mode: input.purposeEnforcement,
          statement: purpose,
          threshold_basis_points: input.thresholdBasisPoints?.trim()
            ? Number(input.thresholdBasisPoints)
            : null,
        }
      : null,
    max_depth: Number(input.maxDepth),
    name: input.name?.trim() ? input.name.trim() : defaultDelegationName(capabilities),
    requires_approval: Boolean(input.requiresApproval),
    resource_scope: allowedPaths.length ? allowedPaths : null,
    sender_constrained: Boolean(input.senderConstrained),
    task: task ? task : null,
    ttl_seconds: Number(input.ttlSeconds),
  };

  const response = await createResource<GrantDelegationResponse, GrantDelegationRequest>(
    getAgentGrantEndpoint(orgSlug, tenantSlug, agentId),
    body,
  );

  return {
    delegationId: response.delegation_id,
    expiresAt: response.expires_at,
    taskToken: response.task_token,
  };
}

type AuthorizeCheckRequest = {
  action?: string | null;
  method?: string | null;
  path?: string | null;
};

type AuthorizeCheckResponse = {
  decision: string;
  reason: string;
};

export type AuthorizationCheckResult = {
  isAllowed: boolean;
  reason: string;
};

export type AuthorizationCheck = { action: string } | { method: string; path: string };

export async function checkAgentAuthorization(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  check: AuthorizationCheck,
): Promise<AuthorizationCheckResult> {
  const body: AuthorizeCheckRequest =
    'action' in check ? { action: check.action } : { method: check.method, path: check.path };

  const response = await createResource<AuthorizeCheckResponse, AuthorizeCheckRequest>(
    getAgentAuthorizeCheckEndpoint(orgSlug, tenantSlug, agentId),
    body,
  );

  return {
    isAllowed: response.decision === 'allow',
    reason: response.reason,
  };
}
