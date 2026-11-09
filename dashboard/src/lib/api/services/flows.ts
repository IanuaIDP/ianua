import { apiClient } from '@/lib/api/client';
import { createResource, deleteResource, getList } from '@/lib/api/crud';
import type {
  Flow,
  FlowAction,
  FlowList,
  FlowNode,
  FlowNodeStatus,
  FlowStatus,
} from '@/types/flow';
import type { FlowNodeDraft } from '@/types/flow-builder';
import { toDataClassLevel } from '@/utils/classification';

type FlowNodeResponse = {
  agent_id: string;
  approval_classes: string[];
  error_message?: string | null;
  goal: string;
  max_steps: number;
  output?: string | null;
  output_exposure: string;
  provider_id: string;
  purpose: string[];
  run_id?: string | null;
  status: string;
  tool_names: string[];
};

type FlowResponse = {
  created_at: string;
  current_stage: number;
  description?: string | null;
  id: string;
  name: string;
  stages: FlowNodeResponse[][];
  status: string;
};

type FlowsResponse = {
  items: FlowResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantFlowsParams = {
  after?: string;
  limit?: number;
};

function toFlowStatus(value: string): FlowStatus {
  const normalized = value?.toLowerCase();

  if (normalized === 'completed') {
    return 'Completed';
  }

  if (normalized === 'failed') {
    return 'Failed';
  }

  if (normalized === 'cancelled' || normalized === 'canceled') {
    return 'Canceled';
  }

  return 'Running';
}

function toFlowNodeStatus(value: string): FlowNodeStatus {
  const normalized = value?.toLowerCase();

  if (normalized === 'dispatched') {
    return 'Dispatched';
  }

  if (normalized === 'completed') {
    return 'Completed';
  }

  if (normalized === 'failed') {
    return 'Failed';
  }

  return 'Pending';
}

function toFlowNode(response: FlowNodeResponse): FlowNode {
  return {
    agentId: response.agent_id,
    approvalClasses: response.approval_classes ?? [],
    errorMessage: response.error_message ?? null,
    goal: response.goal,
    maxSteps: response.max_steps,
    output: response.output ?? null,
    outputExposure: toDataClassLevel(response.output_exposure),
    providerId: response.provider_id,
    purpose: response.purpose ?? [],
    runId: response.run_id ?? null,
    status: toFlowNodeStatus(response.status),
    toolNames: response.tool_names ?? [],
  };
}

function toFlow(response: FlowResponse): Flow {
  return {
    createdAt: response.created_at,
    currentStage: response.current_stage,
    description: response.description ?? null,
    id: response.id,
    name: response.name,
    stages: (response.stages ?? []).map((stage) => stage.map(toFlowNode)),
    status: toFlowStatus(response.status),
  };
}

function getTenantFlowsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/flows`;
}

type CreateFlowNodeRequest = {
  agent_id: string;
  approval_classes?: string[];
  ask_past_micros?: number;
  goal: string;
  max_steps?: number;
  provider_id: string;
  purpose: string[];
  spend_cap_micros?: number;
  tool_names?: string[];
};

type CreateFlowRequest = {
  description?: string | null;
  name: string;
  stages: CreateFlowNodeRequest[][];
};

export type CreateTenantFlowPayload = {
  description?: string | null;
  name: string;
  stages: FlowNodeDraft[][];
};

function toCreateFlowNodeRequest(node: FlowNodeDraft): CreateFlowNodeRequest {
  return {
    agent_id: node.agentId,
    approval_classes: node.approvalClasses,
    ask_past_micros: node.askPastMicros,
    goal: node.goal,
    max_steps: node.maxSteps,
    provider_id: node.providerId,
    purpose: node.purpose,
    spend_cap_micros: node.spendCapMicros,
    tool_names: node.toolNames,
  };
}

export async function getTenantFlows(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantFlowsParams,
): Promise<FlowList> {
  const response = await getList<FlowsResponse>(getTenantFlowsEndpoint(orgSlug, tenantSlug), {
    params: { after: params?.after, limit: params?.limit },
  });

  return {
    items: response.items.map(toFlow),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantFlow(
  orgSlug: string,
  tenantSlug: string,
  flowId: string,
): Promise<Flow> {
  const response = await apiClient.get<FlowResponse>(
    `${getTenantFlowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(flowId)}`,
  );

  return toFlow(response.data);
}

export async function createTenantFlow(
  orgSlug: string,
  tenantSlug: string,
  payload: CreateTenantFlowPayload,
): Promise<Flow> {
  const response = await createResource<FlowResponse, CreateFlowRequest>(
    getTenantFlowsEndpoint(orgSlug, tenantSlug),
    {
      description: payload.description || null,
      name: payload.name,
      stages: payload.stages.map((stage) => stage.map(toCreateFlowNodeRequest)),
    },
  );

  return toFlow(response);
}

export async function cancelTenantFlow(
  orgSlug: string,
  tenantSlug: string,
  flowId: string,
): Promise<Flow> {
  const response = await apiClient.post<FlowResponse>(
    `${getTenantFlowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(flowId)}/cancel`,
  );

  return toFlow(response.data);
}

// Requires the flow to have already finished (completed, failed, or
// cancelled) — this endpoint enforces it server-side; the UI only offers
// "Delete" once a flow is no longer running.
export async function deleteTenantFlow(
  orgSlug: string,
  tenantSlug: string,
  flowId: string,
): Promise<void> {
  await deleteResource<void>(getTenantFlowsEndpoint(orgSlug, tenantSlug), flowId);
}

export async function executeTenantFlowAction(
  orgSlug: string,
  tenantSlug: string,
  flow: Flow,
  action: FlowAction,
): Promise<void> {
  if (action === 'Cancel') {
    await cancelTenantFlow(orgSlug, tenantSlug, flow.id);
    return;
  }

  await deleteTenantFlow(orgSlug, tenantSlug, flow.id);
}
