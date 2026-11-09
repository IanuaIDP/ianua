import { apiClient } from '@/lib/api/client';
import type { WorkflowRisk } from '@/types/workflow-risk';

type RiskResponse = {
  created_at: string;
  effect: string;
  id: string;
  integration: string;
  operation: string;
  raised_by: string;
  updated_at: string;
};

function getRisksEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows/risks`;
}

function toRisk(response: RiskResponse): WorkflowRisk {
  return {
    createdAt: response.created_at,
    effect: response.effect,
    id: response.id,
    integration: response.integration,
    operation: response.operation,
    raisedBy: response.raised_by,
    updatedAt: response.updated_at,
  };
}

/** Every operation the tenant raised, oldest first. */
export async function getWorkflowRisks(
  orgSlug: string,
  tenantSlug: string,
): Promise<WorkflowRisk[]> {
  const { data } = await apiClient.get<RiskResponse[]>(getRisksEndpoint(orgSlug, tenantSlug));

  return data.map(toRisk);
}

/** Makes the tenant treat one operation as `effect`. A workflow calling it then needs an approval. */
export async function raiseWorkflowRisk(
  orgSlug: string,
  tenantSlug: string,
  input: { effect: string; integration: string; operation: string },
): Promise<WorkflowRisk> {
  const { data } = await apiClient.post<RiskResponse>(getRisksEndpoint(orgSlug, tenantSlug), input);

  return toRisk(data);
}

/** Changes what a raised operation counts as. */
export async function changeWorkflowRisk(
  orgSlug: string,
  tenantSlug: string,
  riskId: string,
  effect: string,
): Promise<WorkflowRisk> {
  const { data } = await apiClient.patch<RiskResponse>(
    `${getRisksEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(riskId)}`,
    { effect },
  );

  return toRisk(data);
}

/** Lets the operation count as its integration declares again. */
export async function removeWorkflowRisk(
  orgSlug: string,
  tenantSlug: string,
  riskId: string,
): Promise<void> {
  await apiClient.delete(`${getRisksEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(riskId)}`);
}
