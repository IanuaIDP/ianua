import { apiClient } from '@/lib/api/client';
import { buildSortParam } from '@/lib/api/crud';
import type { WorkflowGraph, WorkflowStepPosition, WorkflowTrigger } from '@/types/workflow-graph';
import type {
  Workflow,
  WorkflowList,
  WorkflowNeedsAccount,
  WorkflowSortField,
} from '@/types/workflows';

type NeedsAccountResponse = { account_id: string; at: string; reason: string };

type WorkflowResponse = {
  created_at: string;
  created_by: string;
  description?: string | null;
  edited_by: string;
  failure_alert: string;
  graph: WorkflowGraph;
  id: string;
  layout: WorkflowStepPosition[];
  name: string;
  needs_account?: NeedsAccountResponse | null;
  published_by?: string | null;
  revision: string;
  run_limit_seconds: number;
  status: string;
  trigger: WorkflowTrigger;
  updated_at: string;
  version: number;
};

type WorkflowsResponse = {
  items: WorkflowResponse[];
  limit: number;
  next_cursor?: string | null;
};

type GetWorkflowsParams = {
  after?: string;
  limit?: number;
  sortDirection?: 'asc' | 'desc';
  sortField?: WorkflowSortField;
};

function getWorkflowsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows`;
}

function toNeedsAccount(response: NeedsAccountResponse): WorkflowNeedsAccount {
  return { accountId: response.account_id, at: response.at, reason: response.reason };
}

export function toWorkflow(response: WorkflowResponse): Workflow {
  return {
    createdAt: response.created_at,
    createdBy: response.created_by,
    description: response.description ?? null,
    editedBy: response.edited_by,
    failureAlert: response.failure_alert,
    graph: response.graph,
    id: response.id,
    layout: response.layout,
    name: response.name,
    needsAccount: response.needs_account ? toNeedsAccount(response.needs_account) : null,
    publishedBy: response.published_by ?? null,
    revision: response.revision,
    runLimitSeconds: response.run_limit_seconds,
    status: response.status,
    trigger: response.trigger,
    updatedAt: response.updated_at,
    version: response.version,
  };
}

/** One page of the tenant's workflows: the latest version of each. */
export async function getWorkflows(
  orgSlug: string,
  tenantSlug: string,
  { after, limit, sortDirection, sortField }: GetWorkflowsParams = {},
): Promise<WorkflowList> {
  const { data } = await apiClient.get<WorkflowsResponse>(
    getWorkflowsEndpoint(orgSlug, tenantSlug),
    {
      params: { after, limit, sort: buildSortParam(sortField, sortDirection) },
    },
  );

  return { items: data.items.map(toWorkflow), nextCursor: data.next_cursor ?? null };
}

/** The workflow's latest version, draft or not. */
export async function getWorkflow(orgSlug: string, tenantSlug: string, workflowId: string) {
  const { data } = await apiClient.get<WorkflowResponse>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(workflowId)}`,
  );

  return toWorkflow(data);
}

/** One version of a workflow by its number. */
export async function getWorkflowVersion(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  version: number,
) {
  const { data } = await apiClient.get<WorkflowResponse>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(workflowId)}/versions/${version}`,
  );

  return toWorkflow(data);
}
