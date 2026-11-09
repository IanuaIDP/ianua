import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { RouteFormInput } from '@/schemas/route-schemas';
import type { PermissionValue } from '@/types/permission';
import type {
  PathRewrite,
  Route,
  RouteAction,
  RouteCustomPermission,
  RouteList,
  RoutePolicy,
  RouteSortDirection,
  RouteSortField,
  RouteStatus,
} from '@/types/route';
import { formatBackendDate } from '@/utils/date';

type RoutePolicyResponse =
  | string
  | { RequireCustomPermission?: { action?: string | null; resource?: string | null }[] | null }
  | { RequireScope?: string[] | null }
  | { RequireSystemPermission?: PermissionValue[] | null }
  | null;

type PathRewriteResponse = {
  mode?: string | null;
  template?: string | null;
};

type RouteResponse = {
  action_class?: string | null;
  attack_mode_until?: string | null;
  conditions?: unknown[] | null;
  created_at?: string | null;
  data_class?: string | null;
  hosts?: string[] | null;
  id: string;
  methods?: string[] | null;
  name?: string | null;
  path_pattern?: string | null;
  path_rewrite?: PathRewriteResponse | null;
  pipeline_id?: string | null;
  policy?: RoutePolicyResponse;
  priority?: number | null;
  reach?: string | null;
  service_id?: string | null;
  status?: string | null;
  updated_at?: string | null;
  workflow_use?: string | null;
};

type RouteListResponse = {
  items: RouteResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantRoutesParams = {
  after?: string;
  limit?: number;
  sortDirection?: RouteSortDirection;
  sortField?: RouteSortField;
};

type RoutePolicyRequest =
  | 'Authenticated'
  | 'Public'
  | { RequireCustomPermission: RouteCustomPermission[] }
  | { RequireScope: string[] }
  | { RequireSystemPermission: PermissionValue[] };

type PathRewriteRequest =
  { mode: 'keep' } | { mode: 'strip_prefix' } | { mode: 'template'; template: string };

type UpsertRouteRequest = {
  hosts: string[];
  methods: string[];
  name: string;
  path_pattern: string;
  path_rewrite: PathRewriteRequest;
  pipeline_id: string;
  policy: RoutePolicyRequest;
  priority: number;
  service_id: string;
};

function toRouteStatus(value?: string | null): RouteStatus {
  return value === 'Disabled' ? 'Disabled' : 'Active';
}

function toRoutePolicy(value?: RoutePolicyResponse): RoutePolicy {
  if (value === 'Authenticated') {
    return 'Authenticated';
  }

  if (!value || typeof value !== 'object') {
    return 'Public';
  }

  if ('RequireSystemPermission' in value && value.RequireSystemPermission) {
    return { RequireSystemPermission: value.RequireSystemPermission };
  }

  if ('RequireCustomPermission' in value && value.RequireCustomPermission) {
    return {
      RequireCustomPermission: value.RequireCustomPermission.map((permission) => ({
        action: permission.action ?? '',
        resource: permission.resource ?? '',
      })),
    };
  }

  if ('RequireScope' in value && value.RequireScope) {
    return { RequireScope: value.RequireScope };
  }

  return 'Public';
}

function toRoutePolicyRequest(payload: RouteFormInput): RoutePolicyRequest {
  switch (payload.policyKind) {
    case 'RequireCustomPermission':
      return { RequireCustomPermission: payload.customPermissions };
    case 'RequireScope':
      return { RequireScope: payload.scopes };
    case 'RequireSystemPermission':
      return { RequireSystemPermission: payload.systemPermissions };
    default:
      return payload.policyKind;
  }
}

function toPathRewrite(value?: PathRewriteResponse | null): PathRewrite {
  if (value?.mode === 'strip_prefix') {
    return { mode: 'strip_prefix' };
  }

  if (value?.mode === 'template') {
    return { mode: 'template', template: value.template ?? '' };
  }

  return { mode: 'keep' };
}

function toPathRewriteRequest(payload: RouteFormInput): PathRewriteRequest {
  if (payload.pathRewriteMode === 'template') {
    return { mode: 'template', template: payload.pathRewriteTemplate.trim() };
  }

  return { mode: payload.pathRewriteMode };
}

function toRoute(response: RouteResponse): Route {
  return {
    actionClass: response.action_class ?? null,
    attackModeUntil: response.attack_mode_until ?? null,
    conditions: response.conditions ?? [],
    created: formatBackendDate(response.created_at),
    dataClass: response.data_class ?? null,
    hosts: response.hosts ?? [],
    id: response.id,
    methods: response.methods ?? [],
    name: response.name || 'Untitled route',
    pathPattern: response.path_pattern ?? '',
    pathRewrite: toPathRewrite(response.path_rewrite),
    pipelineId: response.pipeline_id ?? '',
    policy: toRoutePolicy(response.policy),
    priority: response.priority ?? 0,
    reach: response.reach ?? null,
    serviceId: response.service_id ?? '',
    status: toRouteStatus(response.status),
    workflowUse: response.workflow_use ?? null,
  };
}

function toUpsertRouteRequest(payload: RouteFormInput): UpsertRouteRequest {
  return {
    hosts: payload.hostScope === 'Specific' ? payload.hosts : [],
    methods: payload.methods,
    name: payload.name,
    path_pattern: payload.pathPattern,
    path_rewrite: toPathRewriteRequest(payload),
    pipeline_id: payload.pipelineId,
    policy: toRoutePolicyRequest(payload),
    priority: Number(payload.priority),
    service_id: payload.serviceId,
  };
}

function getTenantRoutesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/routes`;
}

export async function getTenantRoutes(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantRoutesParams,
): Promise<RouteList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<RouteListResponse>(getTenantRoutesEndpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toRoute),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<Route | undefined> {
  const response = await getList<RouteResponse>(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}`,
  );

  return toRoute(response);
}

export async function createTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  payload: RouteFormInput,
): Promise<void> {
  await apiClient.post(
    getTenantRoutesEndpoint(orgSlug, tenantSlug),
    toUpsertRouteRequest(payload) satisfies UpsertRouteRequest,
  );
}

export async function updateTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
  payload: RouteFormInput,
): Promise<void> {
  await apiClient.patch(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}`,
    toUpsertRouteRequest(payload) satisfies UpsertRouteRequest,
  );
}

export async function deleteTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}`,
  );
}

export async function activateTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/activate`,
  );
}

export async function disableTenantRoute(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/disable`,
  );
}

/** Lets workflows call this route as the person each run acts for. */
export async function openRouteToWorkflows(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/open-to-workflows`,
  );
}

export async function closeRouteToWorkflows(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantRoutesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/close-to-workflows`,
  );
}

export async function executeRouteAction(
  orgSlug: string,
  tenantSlug: string,
  route: Route,
  action: RouteAction,
): Promise<void> {
  if (action === 'Enable') {
    await activateTenantRoute(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'Disable') {
    await disableTenantRoute(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'OpenToWorkflows') {
    await openRouteToWorkflows(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'CloseToWorkflows') {
    await closeRouteToWorkflows(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'Delete') {
    await deleteTenantRoute(orgSlug, tenantSlug, route.id);
  }
}
