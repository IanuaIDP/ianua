import { apiClient } from '@/lib/api/client';
import { createResource, getById, getList } from '@/lib/api/crud';
import type { Run, RunPage, RunSummary, RunStep, RunStepOutcome, RunStatus } from '@/types/run';
import { toDataClassLevel } from '@/utils/classification';
import { formatBackendDateTime } from '@/utils/date';

type RunStepResponse = {
  arguments?: string | null;
  detail: string;
  outcome: string;
  seq: number;
  tool?: string | null;
};

type RunStarterResponse = {
  display_name?: string | null;
  id: string;
  kind: string;
};

type RunSummaryResponse = {
  agent_id: string;
  answer?: string | null;
  approval_classes?: string[];
  created_at?: string | null;
  exposure: string;
  goal: string;
  id: string;
  max_steps?: number;
  pending_arguments?: string | null;
  pending_tool?: string | null;
  provider_id: string;
  purpose: string[];
  spend_limit_micros?: number | null;
  spent_micros?: number | null;
  started_by?: RunStarterResponse | null;
  status: string;
  usage?: { input_tokens: number; output_tokens: number } | null;
};

type RunResponse = RunSummaryResponse & { steps: RunStepResponse[] };

type RunPageResponse = {
  items: RunSummaryResponse[];
  next_cursor: string | null;
  limit: number;
};

export type AgentRunsQuery = {
  after?: string;
  limit?: number;
};

export type StartAgentRunPayload = {
  approvalClasses: string[];
  delegationId: string | null;
  goal: string;
  maxSteps: number;
  providerId: string;
  purpose: string[];
};

type StartAgentRunRequest = {
  approval_classes?: string[];
  delegation_id?: string | null;
  goal: string;
  max_steps?: number;
  provider_id: string;
  purpose: string[];
};

type DecideRunRequest = {
  arguments: string;
  tool: string;
};

function toRunStepOutcome(value: string): RunStepOutcome {
  if (value === 'denied' || value === 'answered') {
    return value;
  }

  return 'allowed';
}

function toRunStatus(value: string): RunStatus {
  const normalized = value?.toLowerCase();

  if (normalized === 'awaiting_approval') {
    return 'AwaitingApproval';
  }

  if (normalized === 'completed') {
    return 'Completed';
  }

  if (normalized === 'failed') {
    return 'Failed';
  }

  if (normalized === 'halted') {
    return 'Halted';
  }

  if (normalized === 'paused') {
    return 'Paused';
  }

  if (normalized === 'over_budget') {
    return 'OverBudget';
  }

  if (normalized === 'cancelled' || normalized === 'canceled') {
    return 'Canceled';
  }

  return 'Running';
}

function toRunStep(response: RunStepResponse): RunStep {
  return {
    arguments: response.arguments ?? null,
    detail: response.detail,
    outcome: toRunStepOutcome(response.outcome),
    seq: response.seq,
    tool: response.tool ?? null,
  };
}

function toRunSummary(response: RunSummaryResponse): RunSummary {
  return {
    agentId: response.agent_id,
    answer: response.answer ?? null,
    approvalClasses: response.approval_classes,
    created: formatBackendDateTime(response.created_at),
    exposure: toDataClassLevel(response.exposure),
    goal: response.goal,
    id: response.id,
    maxSteps: response.max_steps,
    pendingArguments: response.pending_arguments ?? null,
    pendingTool: response.pending_tool ?? null,
    providerId: response.provider_id,
    purpose: response.purpose ?? [],
    spendLimitMicros: response.spend_limit_micros ?? null,
    spentMicros: response.spent_micros ?? 0,
    startedBy: response.started_by?.display_name ?? response.started_by?.id ?? null,
    status: toRunStatus(response.status),
    usage: {
      inputTokens: response.usage?.input_tokens ?? 0,
      outputTokens: response.usage?.output_tokens ?? 0,
    },
  };
}

function toRun(response: RunResponse): Run {
  return { ...toRunSummary(response), steps: (response.steps ?? []).map(toRunStep) };
}

function getAgentRunsEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/runs`;
}

export async function getAgentRuns(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  query: AgentRunsQuery = {},
): Promise<RunPage> {
  const response = await getList<RunPageResponse>(
    getAgentRunsEndpoint(orgSlug, tenantSlug, agentId),
    {
      params: { after: query.after, limit: query.limit ?? 20 },
    },
  );

  return {
    items: response.items.map(toRunSummary),
    nextCursor: response.next_cursor,
    limit: response.limit,
  };
}

export async function getAgentRun(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  runId: string,
): Promise<Run> {
  const response = await getById<RunResponse>(
    getAgentRunsEndpoint(orgSlug, tenantSlug, agentId),
    encodeURIComponent(runId),
  );
  return toRun(response);
}

export async function startAgentRun(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  payload: StartAgentRunPayload,
): Promise<Run> {
  const response = await createResource<RunResponse, StartAgentRunRequest>(
    getAgentRunsEndpoint(orgSlug, tenantSlug, agentId),
    {
      approval_classes: payload.approvalClasses,
      delegation_id: payload.delegationId,
      goal: payload.goal,
      max_steps: payload.maxSteps,
      provider_id: payload.providerId,
      purpose: payload.purpose,
    },
  );

  return toRun(response);
}

export async function cancelAgentRun(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  runId: string,
): Promise<Run> {
  const response = await apiClient.post<RunResponse>(
    `${getAgentRunsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(runId)}/cancel`,
  );

  return toRun(response.data);
}

export async function approveAgentRun(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  runId: string,
  tool: string,
  toolArguments: string,
): Promise<Run> {
  const response = await apiClient.post<RunResponse>(
    `${getAgentRunsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(runId)}/approve`,
    { arguments: toolArguments, tool } satisfies DecideRunRequest,
  );

  return toRun(response.data);
}

export async function denyAgentRun(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  runId: string,
): Promise<Run> {
  const response = await apiClient.post<RunResponse>(
    `${getAgentRunsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(runId)}/deny`,
  );

  return toRun(response.data);
}

export async function executeAgentRunAction(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  run: Run,
): Promise<void> {
  await cancelAgentRun(orgSlug, tenantSlug, agentId, run.id);
}
