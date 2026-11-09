import { apiClient } from '@/lib/api/client';

type EventTypeResponse = {
  description: string;
  name: string;
};

type ServiceEventResponse = {
  description: string;
  event: string;
  filters: { description: string; name: string; required: boolean }[];
  integration: string;
  title: string;
};

type TriggerSecretResponse = {
  secret: string;
  trigger_id: string;
};

export type CompanyEventType = EventTypeResponse;

export type WorkflowServiceEvent = ServiceEventResponse;

export type WorkflowTriggerSecret = {
  secret: string;
  triggerId: string;
};

function getTenantEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

function getTriggerSecretEndpoint(orgSlug: string, tenantSlug: string, workflowId: string) {
  return `${getTenantEndpoint(orgSlug, tenantSlug)}/workflows/${encodeURIComponent(workflowId)}/trigger-secret`;
}

function toTriggerSecret(response: TriggerSecretResponse): WorkflowTriggerSecret {
  return { secret: response.secret, triggerId: response.trigger_id };
}

/** The events of the tenant a workflow can start on, such as a user added. */
export async function getCompanyEventTypes(
  orgSlug: string,
  tenantSlug: string,
): Promise<CompanyEventType[]> {
  const { data } = await apiClient.get<EventTypeResponse[]>(
    `${getTenantEndpoint(orgSlug, tenantSlug)}/webhooks/event-types`,
  );

  return data;
}

/** The events connected services can send to start a workflow. */
export async function getWorkflowServiceEvents(orgSlug: string, tenantSlug: string) {
  const { data } = await apiClient.get<WorkflowServiceEvent[]>(
    `${getTenantEndpoint(orgSlug, tenantSlug)}/workflows/events`,
  );

  return data;
}

export async function issueWorkflowTriggerSecret(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
) {
  const { data } = await apiClient.post<TriggerSecretResponse>(
    getTriggerSecretEndpoint(orgSlug, tenantSlug, workflowId),
  );

  return toTriggerSecret(data);
}

export async function rotateWorkflowTriggerSecret(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
) {
  const { data } = await apiClient.post<TriggerSecretResponse>(
    `${getTriggerSecretEndpoint(orgSlug, tenantSlug, workflowId)}/rotate`,
  );

  return toTriggerSecret(data);
}

export async function revokeWorkflowTriggerSecret(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
) {
  await apiClient.delete(getTriggerSecretEndpoint(orgSlug, tenantSlug, workflowId));
}
