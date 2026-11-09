import { isAxiosError } from 'axios';

import { apiClient } from '@/lib/api/client';
import { getWorkflowAccounts } from '@/lib/api/services/workflow-accounts';
import { getWorkflow, getWorkflowVersion, toWorkflow } from '@/lib/api/services/workflows';
import type {
  Evaluation,
  EvaluationCaseBody,
  EvaluationCaseView,
  EvaluationCheckBody,
  EvaluationSet,
} from '@/types/workflow-evaluation';
import type { NewWorkflow, WorkflowDraftEdit, WorkflowProposal } from '@/types/workflow-graph';
import type { ExposureLevel, Workflow, WorkflowAccount } from '@/types/workflows';

type WorkflowResponse = Parameters<typeof toWorkflow>[0];

const ACCOUNTS_PAGE_SIZE = 100;

type StepDataResponse = {
  earlier: {
    source: string;
    values: { description?: string; path: string; whole: boolean }[];
  }[];
  key: string;
};

/** What one step may read, by the trigger and each step before it. */
export type WorkflowStepData = {
  earlier: {
    source: string;
    values: { description: string | null; path: string; whole: boolean }[];
  }[];
  key: string;
};

function getWorkflowsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows`;
}

function getWorkflowEndpoint(orgSlug: string, tenantSlug: string, workflowId: string) {
  return `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(workflowId)}`;
}

/** The workflow's latest version, or the numbered one when `version` is given. */
export function getBuilderWorkflow(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  version?: number,
): Promise<Workflow> {
  return version === undefined
    ? getWorkflow(orgSlug, tenantSlug, workflowId)
    : getWorkflowVersion(orgSlug, tenantSlug, workflowId, version);
}

/** Every connected account of the tenant, read page by page. */
export async function getBuilderAccounts(
  orgSlug: string,
  tenantSlug: string,
): Promise<WorkflowAccount[]> {
  const accounts: WorkflowAccount[] = [];
  let after: string | undefined;

  do {
    const page = await getWorkflowAccounts(orgSlug, tenantSlug, {
      after,
      limit: ACCOUNTS_PAGE_SIZE,
    });

    accounts.push(...page.items);
    after = page.nextCursor ?? undefined;
  } while (after);

  return accounts;
}

/** The first save of a new workflow, which needs a trigger and at least one step. */
export async function createBuilderWorkflow(
  orgSlug: string,
  tenantSlug: string,
  body: NewWorkflow,
): Promise<Workflow> {
  const { data } = await apiClient.post<WorkflowResponse>(
    getWorkflowsEndpoint(orgSlug, tenantSlug),
    body,
  );

  return toWorkflow(data);
}

/** Makes one change to the draft. Answers the draft as saved, with its new revision. */
export async function editWorkflowDraft(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  edit: WorkflowDraftEdit,
): Promise<Workflow> {
  const { data } = await apiClient.patch<WorkflowResponse>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/draft`,
    edit,
  );

  return toWorkflow(data);
}

/** Starts the next draft as a copy of the latest version. `409` when a draft already exists. */
export async function startNextWorkflowDraft(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
): Promise<Workflow> {
  const { data } = await apiClient.post<WorkflowResponse>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/draft`,
  );

  return toWorkflow(data);
}

/** Puts the draft in service. `revision` is the draft as the person reviewed it. */
export async function publishWorkflowDraft(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  revision: string,
): Promise<Workflow> {
  const { data } = await apiClient.post<WorkflowResponse>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/publish`,
    { revision },
  );

  return toWorkflow(data);
}

/** Takes one version out of service for good. */
export async function archiveWorkflowVersion(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  version: number,
): Promise<Workflow> {
  const { data } = await apiClient.post<WorkflowResponse>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/versions/${version}/archive`,
  );

  return toWorkflow(data);
}

/** What each step of the latest version may read. */
export async function getWorkflowStepData(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
): Promise<WorkflowStepData[]> {
  const { data } = await apiClient.get<StepDataResponse[]>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/step-data`,
  );

  return data.map((step) => ({
    earlier: step.earlier.map((source) => ({
      source: source.source,
      values: source.values.map((value) => ({
        description: value.description ?? null,
        path: value.path,
        whole: value.whole,
      })),
    })),
    key: step.key,
  }));
}

/** The stable name of the API's refusal, for the refusals a screen answers differently. */
export function getWorkflowRefusalKey(error: unknown) {
  return isAxiosError<{ key?: string }>(error) ? (error.response?.data?.key ?? null) : null;
}

/** Starts a test of the draft: every step that would change something stands in. */
export async function startWorkflowTest(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  { exposure, input }: { exposure: ExposureLevel; input: unknown },
): Promise<string> {
  const { data } = await apiClient.post<{ execution_id: string }>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/tests`,
    { exposure, input },
  );

  return data.execution_id;
}

export type PickerChoices = {
  choices: { label: string; value: string }[];
  unavailable: string | null;
};

/** Fills a picker through an account. Writes nothing. */
export async function getWorkflowPickerChoices(
  orgSlug: string,
  tenantSlug: string,
  target: { input: string; integration: string; operation: string },
  body: { accountId: string; dependsOn?: unknown },
): Promise<PickerChoices> {
  const { data } = await apiClient.post<{
    choices: { label: string; value: string }[];
    unavailable?: string;
  }>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/operations/${encodeURIComponent(
      target.integration,
    )}/${encodeURIComponent(target.operation)}/inputs/${encodeURIComponent(target.input)}/choices`,
    { account_id: body.accountId, depends_on: body.dependsOn },
  );

  return { choices: data.choices, unavailable: data.unavailable ?? null };
}

export type WorkflowNamedTarget = { id: string; name: string };

/** The routes open to workflows, for a Protected apps step. */
export async function getWorkflowApps(
  orgSlug: string,
  tenantSlug: string,
): Promise<WorkflowNamedTarget[]> {
  const { data } = await apiClient.get<WorkflowNamedTarget[]>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/apps`,
  );

  return data.map(({ id, name }) => ({ id, name }));
}

/** The stream routes open to workflows, for a Protected data step. */
export async function getWorkflowDataTargets(
  orgSlug: string,
  tenantSlug: string,
): Promise<WorkflowNamedTarget[]> {
  const { data } = await apiClient.get<WorkflowNamedTarget[]>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/data`,
  );

  return data.map(({ id, name }) => ({ id, name }));
}

/** Asks the tenant's model to propose steps. Nothing is saved. */
export async function suggestWorkflowSteps(
  orgSlug: string,
  tenantSlug: string,
  body: { after?: { step: string; workflowId: string }; providerId: string; words: string },
): Promise<WorkflowProposal> {
  const { data } = await apiClient.post<WorkflowProposal>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/suggestions`,
    {
      after: body.after ? { step: body.after.step, workflow_id: body.after.workflowId } : undefined,
      provider_id: body.providerId,
      words: body.words,
    },
  );

  return data;
}

type EvaluationCaseResponse = {
  checks?: EvaluationCheckBody[];
  exposure: string;
  input?: unknown;
  name: string;
  withheld: boolean;
};

type EvaluationResponse = {
  cases: {
    case: EvaluationCaseResponse;
    differences?: {
      check?: number;
      found?: string;
      kind: string;
      run_end?: string;
    }[];
    execution_id?: string;
    outcome: string;
    reason?: string;
    withheld_exposure?: string;
  }[];
  created_at: string;
  id: string;
  status: string;
  version: number;
};

function toCaseView(response: EvaluationCaseResponse): EvaluationCaseView {
  return {
    checks: response.checks ?? null,
    exposure: response.exposure,
    input: response.input ?? null,
    name: response.name,
    withheld: response.withheld,
  };
}

function toEvaluation(response: EvaluationResponse): Evaluation {
  return {
    cases: response.cases.map((result) => ({
      case: toCaseView(result.case),
      differences:
        result.differences?.map((difference) => ({
          check: difference.check ?? null,
          found: difference.found ?? null,
          kind: difference.kind,
          runEnd: difference.run_end ?? null,
        })) ?? null,
      executionId: result.execution_id ?? null,
      outcome: result.outcome,
      reason: result.reason ?? null,
      withheldExposure: result.withheld_exposure ?? null,
    })),
    createdAt: response.created_at,
    id: response.id,
    status: response.status,
    version: response.version,
  };
}

/** The workflow's sample cases and its publishing gate. */
export async function getWorkflowEvaluationSet(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
): Promise<EvaluationSet> {
  const { data } = await apiClient.get<{
    cases: EvaluationCaseResponse[];
    publish_gate: string;
  }>(`${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/evaluation-set`);

  return { cases: data.cases.map(toCaseView), publishGate: data.publish_gate };
}

/** Saves every sample case at once. */
export async function saveWorkflowEvaluationSet(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  body: { cases: EvaluationCaseBody[]; publishGate: string },
) {
  await apiClient.put(`${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/evaluation-set`, {
    cases: body.cases,
    publish_gate: body.publishGate,
  });
}

/** Runs the sample cases as tests of the draft. */
export async function startWorkflowEvaluation(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
): Promise<Evaluation> {
  const { data } = await apiClient.post<EvaluationResponse>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/evaluations`,
  );

  return toEvaluation(data);
}

/** The latest evaluations; the first is the one the publish gate reads. */
export async function getWorkflowEvaluations(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
): Promise<Evaluation[]> {
  const { data } = await apiClient.get<EvaluationResponse[]>(
    `${getWorkflowEndpoint(orgSlug, tenantSlug, workflowId)}/evaluations`,
  );

  return data.map(toEvaluation);
}
