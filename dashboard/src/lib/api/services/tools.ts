import { createResource, deleteResource, getList, patchResource } from '@/lib/api/crud';
import type { RegisterToolInput } from '@/schemas/tool-schemas';
import type { Tool, ToolAction, ToolMethod, ToolStatus } from '@/types/tool';
import { toDataClassLevel } from '@/utils/classification';

type ToolResponse = {
  action_class: string;
  classification: string;
  description: string;
  id: string;
  method: string;
  name: string;
  path: string;
  route_id: string;
  schema: Record<string, unknown>;
  status: string;
};

type RegisterToolResponse = {
  id: string;
};

type RegisterToolRequest = {
  description: string;
  method: string;
  name: string;
  path: string;
  route_id: string;
  schema: Record<string, unknown>;
};

type UpdateToolStatusRequest = {
  status: 'active' | 'disabled';
};

function toToolMethod(value: string): ToolMethod {
  const normalizedValue = value?.toUpperCase();

  if (
    normalizedValue === 'GET' ||
    normalizedValue === 'POST' ||
    normalizedValue === 'PUT' ||
    normalizedValue === 'PATCH' ||
    normalizedValue === 'DELETE'
  ) {
    return normalizedValue;
  }

  return 'GET';
}

function toToolStatus(value: string): ToolStatus {
  return value?.toLowerCase() === 'disabled' ? 'Disabled' : 'Active';
}

function toTool(response: ToolResponse): Tool {
  return {
    actionClass: response.action_class ?? '',
    classification: toDataClassLevel(response.classification),
    description: response.description ?? '',
    id: response.id,
    method: toToolMethod(response.method),
    name: response.name ?? '',
    path: response.path ?? '',
    routeId: response.route_id ?? '',
    schema: response.schema ?? {},
    status: toToolStatus(response.status),
  };
}

function getTenantToolsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/tools`;
}

export async function getTenantTools(orgSlug: string, tenantSlug: string): Promise<Tool[]> {
  const response = await getList<ToolResponse[]>(getTenantToolsEndpoint(orgSlug, tenantSlug));

  return response.map(toTool);
}

export async function registerTenantTool(
  orgSlug: string,
  tenantSlug: string,
  payload: RegisterToolInput,
): Promise<RegisterToolResponse> {
  return createResource<RegisterToolResponse, RegisterToolRequest>(
    getTenantToolsEndpoint(orgSlug, tenantSlug),
    {
      description: payload.description,
      method: payload.method,
      name: payload.name,
      path: payload.path,
      route_id: payload.routeId,
      schema: JSON.parse(payload.schema) as Record<string, unknown>,
    },
  );
}

export async function deleteTenantTool(
  orgSlug: string,
  tenantSlug: string,
  toolId: string,
): Promise<void> {
  await deleteResource<void>(getTenantToolsEndpoint(orgSlug, tenantSlug), toolId);
}

export async function updateTenantToolStatus(
  orgSlug: string,
  tenantSlug: string,
  toolId: string,
  status: ToolStatus,
): Promise<void> {
  await patchResource<void, UpdateToolStatusRequest>(
    getTenantToolsEndpoint(orgSlug, tenantSlug),
    toolId,
    {
      status: status === 'Active' ? 'active' : 'disabled',
    },
  );
}

export async function executeTenantToolAction(
  orgSlug: string,
  tenantSlug: string,
  tool: Tool,
  action: ToolAction,
): Promise<void> {
  if (action === 'Enable tool') {
    await updateTenantToolStatus(orgSlug, tenantSlug, tool.id, 'Active');
    return;
  }

  if (action === 'Disable tool') {
    await updateTenantToolStatus(orgSlug, tenantSlug, tool.id, 'Disabled');
    return;
  }

  await deleteTenantTool(orgSlug, tenantSlug, tool.id);
}
