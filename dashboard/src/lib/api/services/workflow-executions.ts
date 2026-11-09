import { apiClient } from '@/lib/api/client';
import type {
  Execution,
  ExecutionDecided,
  ExecutionKind,
  ExecutionList,
  ExposureLevel,
  StepState,
} from '@/types/workflows';

type LoopProgressResponse = {
  approval?: string | null;
  done: number;
  executions: string[];
  items: number;
};

type StepStateResponse = {
  exposure?: string | null;
  failure?: { code: string; detail: string } | null;
  input?: unknown;
  key: string;
  name: string;
  output?: unknown;
  passes?: LoopProgressResponse | null;
  phase: string;
  port?: string | null;
  withheld: boolean;
};

type ExecutionResponse = {
  acting_for: string;
  cause: string;
  created_at: string;
  deadline: string;
  exposure: string;
  id: string;
  input: unknown;
  input_withheld: boolean;
  mode: string;
  pass?: { execution_id: string; index: number; step: string } | null;
  status: string;
  steps: StepStateResponse[];
  updated_at: string;
  version: number;
  workflow_id: string;
};

type ExecutionsResponse = {
  items: ExecutionResponse[];
  limit: number;
  next_cursor?: string | null;
};

type ExecutionDecidedResponse = { execution_id: string; status: string };

type GetExecutionsParams = {
  after?: string;
  kind?: ExecutionKind;
  limit?: number;
};

function getWorkflowsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows`;
}

function getExecutionEndpoint(orgSlug: string, tenantSlug: string, executionId: string) {
  return `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/executions/${encodeURIComponent(executionId)}`;
}

function toLoopProgress(response: LoopProgressResponse) {
  return {
    approval: response.approval ?? null,
    done: response.done,
    executions: response.executions,
    items: response.items,
  };
}

function toStepState(response: StepStateResponse): StepState {
  return {
    exposure: response.exposure ?? null,
    failure: response.failure ?? null,
    input: response.input,
    key: response.key,
    name: response.name,
    output: response.output,
    passes: response.passes ? toLoopProgress(response.passes) : null,
    phase: response.phase,
    port: response.port ?? null,
    withheld: response.withheld,
  };
}

export function toExecution(response: ExecutionResponse): Execution {
  return {
    actingFor: response.acting_for,
    cause: response.cause,
    createdAt: response.created_at,
    deadline: response.deadline,
    exposure: response.exposure,
    id: response.id,
    input: response.input,
    inputWithheld: response.input_withheld,
    mode: response.mode,
    pass: response.pass
      ? {
          executionId: response.pass.execution_id,
          index: response.pass.index,
          step: response.pass.step,
        }
      : null,
    status: response.status,
    steps: response.steps.map(toStepState),
    updatedAt: response.updated_at,
    version: response.version,
    workflowId: response.workflow_id,
  };
}

function toExecutionDecided(response: ExecutionDecidedResponse): ExecutionDecided {
  return { executionId: response.execution_id, status: response.status };
}

function toExecutionList(data: ExecutionsResponse): ExecutionList {
  return { items: data.items.map(toExecution), nextCursor: data.next_cursor ?? null };
}

function toKindParam(kind: ExecutionKind | undefined) {
  return kind === 'tests' ? 'tests' : undefined;
}

/** One page of every run in the tenant, newest first. */
export async function getWorkflowExecutions(
  orgSlug: string,
  tenantSlug: string,
  { after, kind, limit }: GetExecutionsParams = {},
) {
  const { data } = await apiClient.get<ExecutionsResponse>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/executions`,
    { params: { after, kind: toKindParam(kind), limit } },
  );

  return toExecutionList(data);
}

/** One page of one workflow's runs, newest first. */
export async function getWorkflowRuns(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  { after, kind, limit }: GetExecutionsParams = {},
) {
  const { data } = await apiClient.get<ExecutionsResponse>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(workflowId)}/executions`,
    { params: { after, kind: toKindParam(kind), limit } },
  );

  return toExecutionList(data);
}

/** Where one run stands. Data above the caller's clearance is withheld. */
export async function getWorkflowExecution(
  orgSlug: string,
  tenantSlug: string,
  executionId: string,
) {
  const { data } = await apiClient.get<ExecutionResponse>(
    getExecutionEndpoint(orgSlug, tenantSlug, executionId),
  );

  return toExecution(data);
}

/** One page of the passes a run's loop steps started, newest first. */
export async function getWorkflowExecutionPasses(
  orgSlug: string,
  tenantSlug: string,
  executionId: string,
  { after, limit }: { after?: string; limit?: number } = {},
) {
  const { data } = await apiClient.get<ExecutionsResponse>(
    `${getExecutionEndpoint(orgSlug, tenantSlug, executionId)}/passes`,
    { params: { after, limit } },
  );

  return toExecutionList(data);
}

/** Starts the published version of a by-hand workflow. */
export async function startWorkflowRun(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  { exposure, input }: { exposure: ExposureLevel; input?: unknown },
) {
  const { data } = await apiClient.post<ExecutionDecidedResponse>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(workflowId)}/executions`,
    { exposure, input },
  );

  return toExecutionDecided(data);
}

async function postRunAction(
  orgSlug: string,
  tenantSlug: string,
  executionId: string,
  action: 'cancel' | 'rerun' | 'retry',
) {
  const { data } = await apiClient.post<ExecutionDecidedResponse>(
    `${getExecutionEndpoint(orgSlug, tenantSlug, executionId)}/${action}`,
  );

  return toExecutionDecided(data);
}

/** Stops a running run and the agent runs it started. */
export function cancelWorkflowRun(orgSlug: string, tenantSlug: string, executionId: string) {
  return postRunAction(orgSlug, tenantSlug, executionId, 'cancel');
}

/** Starts a failed or timed-out run again from its trigger, as a new run. */
export function rerunWorkflowRun(orgSlug: string, tenantSlug: string, executionId: string) {
  return postRunAction(orgSlug, tenantSlug, executionId, 'rerun');
}

/** Starts a failed or timed-out run again from what did not finish, as a new run. */
export function retryWorkflowRun(orgSlug: string, tenantSlug: string, executionId: string) {
  return postRunAction(orgSlug, tenantSlug, executionId, 'retry');
}
