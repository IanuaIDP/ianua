import { apiClient } from '@/lib/api/client';
import { buildSortParam, getById, getList } from '@/lib/api/crud';
import { MAX_TENANT_AGENTS } from '@/constants/tenant-agent';
import type { TenantAgentFormInput } from '@/schemas/tenant-agent-schemas';
import type {
  TenantAgent,
  TenantAgentAction,
  TenantAgentOwner,
  TenantAgentOwnerKind,
  TenantAgentSortDirection,
  TenantAgentSortField,
  TenantAgentStanding,
  TenantAgentStatus,
} from '@/types/tenant-agent';
import { formatBackendDateTime } from '@/utils/date';

type TenantAgentOwnerResponse = {
  display_name?: string | null;
  id: string;
  kind: TenantAgentOwnerKind;
};

type TenantAgentAttestationPolicyResponse = {
  allowed_origins?: string[] | null;
  methods?: string[] | null;
  reattest_interval_seconds?: number | null;
  workload_trusts?: { issuer: string; method: string; subject: string }[] | null;
} | null;

type TenantAgentResponse = {
  attestation_policy?: TenantAgentAttestationPolicyResponse;
  created_at: string;
  description?: string | null;
  id: string;
  name: string;
  offer_expires_at?: string | null;
  offered_to?: TenantAgentOwnerResponse | null;
  owner: TenantAgentOwnerResponse;
  re_attest_every?: number | null;
  standing: TenantAgentStanding;
  status: string;
  trusted_methods?: string[] | null;
  updated_at?: string | null;
};

type TenantAgentsResponse = {
  items: TenantAgentResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantAgentsParams = {
  sortDirection?: TenantAgentSortDirection;
  sortField?: TenantAgentSortField;
};

type UpdateAgentRequest = {
  description: string | null;
  name: string;
};

type CreateAgentResponse = {
  id: string;
};

type SuspendAllAgentsResponse = {
  suspended_count: number;
};

type CreateAgentRequest = UpdateAgentRequest;

type OfferAgentRequest = {
  recipient: string;
};

function toTenantAgentStatus(value: string): TenantAgentStatus {
  if (value === 'Suspended' || value === 'Revoked') {
    return value;
  }

  return 'Active';
}

function toTenantAgentOwner(response: TenantAgentOwnerResponse): TenantAgentOwner {
  return {
    displayName: response.display_name ?? undefined,
    id: response.id,
    kind: response.kind,
  };
}

function toTenantAgent(response: TenantAgentResponse): TenantAgent {
  return {
    attestationMethods: response.trusted_methods ?? response.attestation_policy?.methods ?? [],
    attestationOrigins: response.attestation_policy?.allowed_origins ?? [],
    created: formatBackendDateTime(response.created_at),
    description: response.description ?? '',
    id: response.id,
    name: response.name,
    offerExpiresAt: response.offer_expires_at ?? null,
    offeredTo: response.offered_to ? toTenantAgentOwner(response.offered_to) : null,
    owner: toTenantAgentOwner(response.owner),
    reattestIntervalSeconds:
      response.re_attest_every ?? response.attestation_policy?.reattest_interval_seconds ?? null,
    standing: response.standing,
    status: toTenantAgentStatus(response.status),
    updated: formatBackendDateTime(response.updated_at),
    workloadTrusts: response.attestation_policy?.workload_trusts ?? [],
  };
}

function getTenantAgentsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents`;
}

export async function getTenantAgents(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantAgentsParams,
): Promise<TenantAgent[]> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const agents: TenantAgent[] = [];
  let after: string | undefined;

  // Callers filter by status and fill pickers, and the API has no status filter here.
  do {
    const response: TenantAgentsResponse = await getList<TenantAgentsResponse>(
      getTenantAgentsEndpoint(orgSlug, tenantSlug),
      {
        params: {
          after,
          limit: MAX_TENANT_AGENTS,
          sort,
        },
      },
    );

    agents.push(...response.items.map(toTenantAgent));
    after = response.next_cursor ?? undefined;
  } while (after);

  return agents;
}

export async function getTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<TenantAgent> {
  const response = await getById<TenantAgentResponse>(
    getTenantAgentsEndpoint(orgSlug, tenantSlug),
    agentId,
  );

  return toTenantAgent(response);
}

export async function createTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  payload: TenantAgentFormInput,
  owner: TenantAgentOwner | null,
): Promise<{ agentId: string }> {
  const response = await apiClient.post<CreateAgentResponse>(
    getTenantAgentsEndpoint(orgSlug, tenantSlug),
    {
      description: payload.description || null,
      name: payload.name,
    } satisfies CreateAgentRequest,
  );

  // The API makes the caller the owner; another owner has to accept an offer.
  if (owner?.kind === 'user') {
    await offerTenantAgent(orgSlug, tenantSlug, response.data.id, owner.id);
  }

  return { agentId: response.data.id };
}

export async function offerTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  recipient: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/offer`,
    { recipient } satisfies OfferAgentRequest,
  );
}

export async function updateTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  payload: TenantAgentFormInput,
): Promise<void> {
  await apiClient.patch(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}`,
    { description: payload.description || null, name: payload.name } satisfies UpdateAgentRequest,
  );
}

export async function suspendTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/suspend`,
  );
}

export async function suspendAllTenantAgents(orgSlug: string, tenantSlug: string): Promise<number> {
  const response = await apiClient.post<SuspendAllAgentsResponse>(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/suspend-all`,
  );

  return response.data.suspended_count;
}

export async function resumeTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/resume`,
  );
}

export async function revokeTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/revoke`,
  );
}

type SetAttestationPolicyRequest = {
  allowed_origins: string[];
  methods: string[];
  reattest_interval_seconds: number;
};

export async function setTenantAgentAttestationPolicy(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  methods: string[],
  reattestIntervalSeconds: number,
  allowedOrigins: string[],
): Promise<void> {
  await apiClient.put(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/attestation-policy`,
    {
      allowed_origins: allowedOrigins,
      methods,
      reattest_interval_seconds: reattestIntervalSeconds,
    } satisfies SetAttestationPolicyRequest,
  );
}

export async function requireTenantAgentReattestation(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      agentId,
    )}/require-reattestation`,
  );
}

export async function containTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<{ revokedCount: number }> {
  const response = await apiClient.post<{ revoked_count: number }>(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/contain`,
  );

  return { revokedCount: response.data.revoked_count };
}

type TenantAgentBlastRadiusResponse = {
  agent_count: number;
  delegation_count: number;
};

export type TenantAgentBlastRadius = {
  agentCount: number;
  delegationCount: number;
};

export async function getAgentBlastRadius(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<TenantAgentBlastRadius> {
  const response = await apiClient.get<TenantAgentBlastRadiusResponse>(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/blast-radius`,
  );

  return {
    agentCount: response.data.agent_count,
    delegationCount: response.data.delegation_count,
  };
}

type TenantAgentCredentialResponse = {
  status: string;
};

export async function getTenantAgentActiveCredentialCount(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<number> {
  const response = await apiClient.get<TenantAgentCredentialResponse[]>(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}/credentials`,
  );

  return response.data.filter((credential) => credential.status?.toLowerCase() !== 'revoked')
    .length;
}

export async function executeTenantAgentAction(
  orgSlug: string,
  tenantSlug: string,
  agent: TenantAgent,
  action: TenantAgentAction,
): Promise<void> {
  if (action === 'Suspend') {
    await suspendTenantAgent(orgSlug, tenantSlug, agent.id);
    return;
  }

  if (action === 'Resume') {
    await resumeTenantAgent(orgSlug, tenantSlug, agent.id);
    return;
  }

  if (action === 'Revoke') {
    await revokeTenantAgent(orgSlug, tenantSlug, agent.id);
    return;
  }

  if (action === 'RequireReattestation') {
    await requireTenantAgentReattestation(orgSlug, tenantSlug, agent.id);
    return;
  }

  if (action === 'Contain') {
    await containTenantAgent(orgSlug, tenantSlug, agent.id);
    return;
  }

  if (action === 'Delete') {
    await deleteTenantAgent(orgSlug, tenantSlug, agent.id);
  }
}

/// Forgets a revoked agent. The API refuses this for any other status: revoking
/// is what stops it, deleting is what removes the record.
export async function deleteTenantAgent(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantAgentsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(agentId)}`,
  );
}
