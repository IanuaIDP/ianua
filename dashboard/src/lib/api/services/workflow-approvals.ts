import { apiClient } from '@/lib/api/client';
import { getApiErrorStatus } from '@/lib/api/errors';
import { getWorkflowExecution } from '@/lib/api/services/workflow-executions';
import { getWorkflowVersion } from '@/lib/api/services/workflows';
import { findApprovalStep } from '@/utils/workflow-approvals';
import type { ExecutionDecided, LoopApprovalPage, WorkflowRunStep } from '@/types/workflows';

type ApprovalItemsResponse = {
  action_class: string;
  approvers_needed: number;
  closes_at: string;
  items: { item: unknown; position: number }[];
  limit: number;
  next_cursor?: string | null;
  opened_at: string;
  shared: unknown;
  shown: number;
  summary: string;
  total: number;
};

type ExecutionDecidedResponse = { execution_id: string; status: string };

const ITEMS_PER_PAGE = 20;

function getApprovalEndpoint({ orgSlug, runId, step, tenantSlug }: WorkflowRunStep) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows/executions/${encodeURIComponent(runId)}/approvals/${encodeURIComponent(step)}`;
}

function toExecutionDecided(response: ExecutionDecidedResponse): ExecutionDecided {
  return { executionId: response.execution_id, status: response.status };
}

/**
 * The data an approval step lets through, kept as the API sent it: approving
 * counts only for exactly this data, so it must go back unchanged.
 */
export async function getWorkflowApproval(ref: WorkflowRunStep): Promise<unknown> {
  const response = await apiClient.get<{ shown: unknown }>(getApprovalEndpoint(ref));

  return response.data.shown;
}

/** One page of the items a loop asks a single approval for. Opening a page counts as seen. */
export async function getWorkflowLoopApprovalPage(
  ref: WorkflowRunStep,
  after?: string,
): Promise<LoopApprovalPage> {
  const { data } = await apiClient.get<ApprovalItemsResponse>(`${getApprovalEndpoint(ref)}/items`, {
    params: { after, limit: ITEMS_PER_PAGE },
  });

  return {
    actionClass: data.action_class,
    approversNeeded: data.approvers_needed,
    closesAt: data.closes_at,
    items: data.items,
    limit: data.limit,
    nextCursor: data.next_cursor ?? null,
    openedAt: data.opened_at,
    shared: data.shared,
    shown: data.shown,
    summary: data.summary,
    total: data.total,
  };
}

export async function approveWorkflowStep(
  ref: WorkflowRunStep,
  shown: unknown,
  mfaCode?: string,
): Promise<ExecutionDecided> {
  const { data } = await apiClient.post<ExecutionDecidedResponse>(
    `${getApprovalEndpoint(ref)}/approve`,
    { mfa_code: mfaCode || null, shown },
  );

  return toExecutionDecided(data);
}

export async function approveWorkflowLoopItems(
  ref: WorkflowRunStep,
  mfaCode?: string,
): Promise<ExecutionDecided> {
  const { data } = await apiClient.post<ExecutionDecidedResponse>(
    `${getApprovalEndpoint(ref)}/items/approve`,
    { mfa_code: mfaCode || null },
  );

  return toExecutionDecided(data);
}

/** Refuses the approval, which ends the run. */
export async function denyWorkflowApproval(ref: WorkflowRunStep): Promise<ExecutionDecided> {
  const { data } = await apiClient.post<ExecutionDecidedResponse>(
    `${getApprovalEndpoint(ref)}/deny`,
  );

  return toExecutionDecided(data);
}

/** What the page shows about an approval, and how it was found. */
export type WorkflowApprovalData =
  { kind: 'loop'; page: LoopApprovalPage } | { kind: 'step'; shown: unknown };

/**
 * The approval as the caller may see it. A loop that asks once for every item
 * answers the items; any other approval step answers `422` there and is read
 * as a single step.
 */
export async function loadWorkflowApproval(ref: WorkflowRunStep): Promise<WorkflowApprovalData> {
  try {
    return { kind: 'loop', page: await getWorkflowLoopApprovalPage(ref) };
  } catch (error) {
    if (getApiErrorStatus(error) !== 422) {
      throw error;
    }
  }

  return { kind: 'step', shown: await getWorkflowApproval(ref) };
}

/** The step's name, what it asks and its action class, for someone who may read the run. */
export async function getWorkflowApprovalContext(ref: WorkflowRunStep) {
  const run = await getWorkflowExecution(ref.orgSlug, ref.tenantSlug, ref.runId);
  const version = await getWorkflowVersion(
    ref.orgSlug,
    ref.tenantSlug,
    run.workflowId,
    run.version,
  );

  return findApprovalStep(version.graph, ref.step);
}

/**
 * Whether the step still waits for a yes, read after one was given: the API
 * answers `422` for a step no longer waiting.
 */
export async function isApprovalStillWaiting(data: WorkflowApprovalData, ref: WorkflowRunStep) {
  try {
    await (data.kind === 'loop' ? getWorkflowLoopApprovalPage(ref) : getWorkflowApproval(ref));

    return true;
  } catch (error) {
    return getApiErrorStatus(error) !== 422;
  }
}
