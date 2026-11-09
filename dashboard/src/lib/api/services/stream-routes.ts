import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { StreamRouteFormInput } from '@/schemas/stream-route-schemas';
import { formatBackendDate } from '@/utils/date';
import type {
  StreamBackend,
  StreamPolicy,
  StreamProtocol,
  StreamRoute,
  StreamRouteAction,
  StreamRouteList,
  StreamRouteSortDirection,
  StreamRouteSortField,
  StreamSni,
} from '@/types/stream-route';

type StreamSniResponse = {
  mode?: string | null;
  names?: string[] | null;
};

type StreamRouteResponse = {
  access?: Record<string, unknown> | null;
  backends?: { host?: string | null; port?: number | null; weight?: number | null }[] | null;
  created_at?: string | null;
  id: string;
  listen_port?: number | null;
  name?: string | null;
  policy?: string | null;
  protocol?: string | null;
  sni?: StreamSniResponse | null;
  status?: string | null;
  timeouts?: { connect_secs?: number | null; idle_secs?: number | null } | null;
  updated_at?: string | null;
  workflow_use?: string | null;
};

type StreamRouteListResponse = {
  items: StreamRouteResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetStreamRoutesParams = {
  after?: string;
  limit?: number;
  sortDirection?: StreamRouteSortDirection;
  sortField?: StreamRouteSortField;
};

function endpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/stream-routes`;
}

function toProtocol(value?: string | null): StreamProtocol {
  switch (value) {
    case 'tls_terminate':
    case 'tls_passthrough':
    case 'udp':
      return value;
    default:
      return 'tcp';
  }
}

/// Anything but an explicit `mutual_tls` reads as public. Erring towards the
/// weaker label is right for a *display*: it never claims a port is protected
/// when the API did not say so.
function toPolicy(value?: string | null): StreamPolicy {
  return value === 'mutual_tls' || value === 'tunnel' ? value : 'public';
}

function toSni(value?: StreamSniResponse | null): StreamSni {
  if (value?.mode === 'only' && value.names?.length) {
    return { mode: 'only', names: value.names };
  }
  return { mode: 'any' };
}

function toBackends(response: StreamRouteResponse): StreamBackend[] {
  return (response.backends ?? []).map((backend) => ({
    host: backend.host ?? '',
    port: backend.port ?? 0,
    weight: backend.weight ?? 1,
  }));
}

function toStreamRoute(response: StreamRouteResponse): StreamRoute {
  return {
    access: response.access ?? null,
    backends: toBackends(response),
    created: formatBackendDate(response.created_at),
    id: response.id,
    listenPort: response.listen_port ?? 0,
    name: response.name || 'Untitled port',
    policy: toPolicy(response.policy),
    protocol: toProtocol(response.protocol),
    sni: toSni(response.sni),
    status: response.status === 'Disabled' ? 'Disabled' : 'Active',
    timeouts: {
      connectSecs: response.timeouts?.connect_secs ?? 0,
      idleSecs: response.timeouts?.idle_secs ?? 0,
    },
    workflowUse: response.workflow_use ?? null,
  };
}

/// Everything a port may change after it is open. The protocol and the listen
/// port are absent by design: either is a different socket on a different
/// listener, so the API refuses to change them in place.
function toUpdateRequest(payload: StreamRouteFormInput) {
  const names = payload.sniNames.map((name) => name.trim()).filter(Boolean);

  return {
    backends: payload.backends.map((backend) => ({
      host: backend.host.trim(),
      port: Number(backend.port),
      weight: Number(backend.weight),
    })),
    access: payload.access ?? undefined,
    name: payload.name,
    policy: payload.policy,
    sni: payload.sniRestricted ? { mode: 'only', names } : { mode: 'any' },
    timeouts: {
      connect_secs: Number(payload.connectSecs),
      idle_secs: Number(payload.idleSecs),
    },
  };
}

function toRequest(payload: StreamRouteFormInput) {
  return {
    ...toUpdateRequest(payload),
    listen_port: Number(payload.listenPort),
    protocol: payload.protocol,
  };
}

export async function getTenantStreamRoutes(
  orgSlug: string,
  tenantSlug: string,
  params?: GetStreamRoutesParams,
): Promise<StreamRouteList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<StreamRouteListResponse>(endpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toStreamRoute),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<StreamRoute> {
  const { data } = await apiClient.get<StreamRouteResponse>(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`,
  );
  return toStreamRoute(data);
}

export async function createTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  payload: StreamRouteFormInput,
): Promise<string> {
  const { data } = await apiClient.post<{ id: string }>(
    endpoint(orgSlug, tenantSlug),
    toRequest(payload),
  );
  return data.id;
}

export async function updateTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  id: string,
  payload: StreamRouteFormInput,
): Promise<void> {
  await apiClient.patch(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`,
    toUpdateRequest(payload),
  );
}

export async function deleteTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<void> {
  await apiClient.delete(`${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`);
}

export async function activateTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<void> {
  await apiClient.post(`${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}/activate`);
}

export async function disableTenantStreamRoute(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<void> {
  await apiClient.post(`${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}/disable`);
}

/** Lets workflows reach the system behind this route, signing in with this login. */
export async function openStreamRouteToWorkflows(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
  login: {
    loginPassword: string;
    loginUser: string;
    tls: 'off' | 'required';
    tlsAuthority?: string;
    tlsServerName?: string;
  },
): Promise<void> {
  await apiClient.post(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/open-to-workflows`,
    {
      login_password: login.loginPassword,
      login_user: login.loginUser,
      tls: login.tls,
      tls_authority: login.tlsAuthority || null,
      tls_server_name: login.tlsServerName || null,
    },
  );
}

export async function closeStreamRouteToWorkflows(
  orgSlug: string,
  tenantSlug: string,
  routeId: string,
): Promise<void> {
  await apiClient.post(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(routeId)}/close-to-workflows`,
  );
}

export async function executeStreamRouteAction(
  orgSlug: string,
  tenantSlug: string,
  route: StreamRoute,
  action: StreamRouteAction,
): Promise<void> {
  if (action === 'Enable') {
    await activateTenantStreamRoute(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'Disable') {
    await disableTenantStreamRoute(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'CloseToWorkflows') {
    await closeStreamRouteToWorkflows(orgSlug, tenantSlug, route.id);
    return;
  }

  if (action === 'Delete') {
    await deleteTenantStreamRoute(orgSlug, tenantSlug, route.id);
  }
}
