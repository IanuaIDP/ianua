import { DEFAULT_DISCOVERY_REFRESH_SECS, SIGN_IN_ADDRESS_KEYS } from '@/constants/service';
import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { AppSignInFormInput } from '@/schemas/app-sign-in-schemas';
import type { ServiceFormInput } from '@/schemas/service-schemas';
import type {
  AppSignIn,
  DiscoveryKind,
  GatewayService,
  GatewayServiceList,
  GatewayServiceSortDirection,
  GatewayServiceSortField,
  HealthCheckTimings,
  SignInAddresses,
} from '@/types/gateway-service';
import type { StickySession, WeightedBackend } from '@/types/route';

const DEFAULT_HEALTH_CHECK_PATH = '/healthz';

type DiscoveryResponse = {
  kind?: string | null;
  name?: string | null;
  refresh_secs?: number | null;
};

type HealthCheckResponse = {
  enabled?: boolean | null;
  healthy_threshold?: number | null;
  interval_secs?: number | null;
  panic_threshold_percent?: number | null;
  path?: string | null;
  timeout_secs?: number | null;
  unhealthy_threshold?: number | null;
};

type TokenAudienceResponse = 'no_token_accepted' | { pinned: string };

type RouteIdentityResponse = 'token' | 'client_certificate';

type UpstreamResponse = {
  backends?: { url?: string | null; weight?: number | null }[] | null;
  discovery?: DiscoveryResponse | null;
  expected_audience?: TokenAudienceResponse | null;
  identity?: RouteIdentityResponse | null;
  preserve_host?: boolean | null;
  sticky_session?: { kind?: string | null; value?: string | null } | null;
  timeout_secs?: number | null;
  url?: string | null;
};

type SignInPathsResponse = Partial<Record<keyof SignInAddresses, string | null>>;

type AppSignInResponse = {
  addresses: SignInAddresses;
  after_sign_in: string;
  hosts: string[];
  paths?: SignInPathsResponse | null;
  prefix: string;
  signed_out_browsers?: string | null;
};

type SignInDeliveryResponse =
  { kind: 'same_host' } | { hosts: string[]; kind: 'own_cookie' } | { kind: 'tokens' };

type GatewayServiceResponse = {
  accepts_app_sign_in_of?: string | null;
  sign_in_delivery?: SignInDeliveryResponse | null;
  app_sign_in?: AppSignInResponse | null;
  created_at?: string | null;
  health_check?: HealthCheckResponse | null;
  id: string;
  name?: string | null;
  status?: string | null;
  tls?: {
    ca_certificates?: string | null;
    client_certificate?: string | null;
    server_name?: string | null;
  } | null;
  updated_at?: string | null;
  upstream?: UpstreamResponse | null;
};

type GatewayServiceListResponse = {
  items: GatewayServiceResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantServicesParams = {
  after?: string;
  limit?: number;
  sortDirection?: GatewayServiceSortDirection;
  sortField?: GatewayServiceSortField;
};

function endpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/services`;
}

function toDiscoveryKind(value?: string | null): DiscoveryKind {
  return value === 'srv' ? 'srv' : 'address';
}

function toStickySession(value?: UpstreamResponse['sticky_session']): StickySession | null {
  switch (value?.kind) {
    case 'ConsumerId':
      return { kind: 'ConsumerId' };
    case 'Cookie':
      return { kind: 'Cookie', value: value.value ?? '' };
    case 'Header':
      return { kind: 'Header', value: value.value ?? '' };
    case 'SourceIp':
      return { kind: 'SourceIp' };
    case 'UserId':
      return { kind: 'UserId' };
    default:
      return null;
  }
}

// The upstream URL appears among the backends only when it was given a weight
// of its own, so it is kept: dropping it would reset that weight to 100.
function toAdditionalBackends(upstream?: UpstreamResponse | null): WeightedBackend[] {
  return (upstream?.backends ?? [])
    .filter((backend) => backend.url)
    .map((backend) => ({ url: backend.url ?? '', weight: backend.weight ?? 0 }));
}

function toHealthCheckTimings(response?: HealthCheckResponse | null): HealthCheckTimings | null {
  if (!response?.enabled) {
    return null;
  }

  return {
    healthyThreshold: response.healthy_threshold ?? 0,
    intervalSecs: response.interval_secs ?? 0,
    panicThresholdPercent: response.panic_threshold_percent ?? 0,
    timeoutSecs: response.timeout_secs ?? 0,
    unhealthyThreshold: response.unhealthy_threshold ?? 0,
  };
}

// Timings the form doesn't show go back as they came, so saving a new path
// keeps them; a service probed for the first time gets the platform's.
function toHealthCheckRequest(payload: ServiceFormInput) {
  const timings = payload.healthCheckTimings;

  return {
    enabled: payload.healthCheckEnabled,
    path: payload.healthCheckPath.trim() || DEFAULT_HEALTH_CHECK_PATH,
    ...(timings && {
      healthy_threshold: timings.healthyThreshold,
      interval_secs: timings.intervalSecs,
      panic_threshold_percent: timings.panicThresholdPercent,
      timeout_secs: timings.timeoutSecs,
      unhealthy_threshold: timings.unhealthyThreshold,
    }),
  };
}

function toMovedPaths(paths?: SignInPathsResponse | null): Partial<SignInAddresses> {
  const moved: Partial<SignInAddresses> = {};
  for (const key of SIGN_IN_ADDRESS_KEYS) {
    const path = paths?.[key];
    if (path) {
      moved[key] = path;
    }
  }
  return moved;
}

function toAppSignIn(response?: AppSignInResponse | null): AppSignIn | null {
  if (!response) {
    return null;
  }

  return {
    addresses: response.addresses,
    afterSignIn: response.after_sign_in,
    hosts: response.hosts,
    paths: toMovedPaths(response.paths),
    prefix: response.prefix,
    signedOutBrowsers: response.signed_out_browsers === 'redirect' ? 'redirect' : 'refuse',
  };
}

function toExpectedAudience(audience?: TokenAudienceResponse | null): string {
  return audience && typeof audience === 'object' ? audience.pinned : '';
}

function toGatewayService(response: GatewayServiceResponse): GatewayService {
  const discovery = response.upstream?.discovery;

  return {
    acceptsAppSignInOf: response.accepts_app_sign_in_of ?? null,
    upstreamTls: response.tls
      ? {
          caCertificates: response.tls.ca_certificates ?? null,
          clientCertificate: response.tls.client_certificate ?? null,
          serverName: response.tls.server_name ?? null,
        }
      : null,
    signInDelivery: response.sign_in_delivery ?? null,
    additionalBackends: toAdditionalBackends(response.upstream),
    appSignIn: toAppSignIn(response.app_sign_in),
    discoveryKind: toDiscoveryKind(discovery?.kind),
    discoveryName: discovery?.name ?? '',
    discoveryRefreshSecs: discovery?.refresh_secs ?? DEFAULT_DISCOVERY_REFRESH_SECS,
    expectedAudience: toExpectedAudience(response.upstream?.expected_audience),
    // `null` means probing is off, which means every backend stays eligible —
    // not that its health is unknown.
    healthCheckEnabled: Boolean(response.health_check?.enabled),
    healthCheckPath: response.health_check?.path ?? DEFAULT_HEALTH_CHECK_PATH,
    healthCheckTimings: toHealthCheckTimings(response.health_check),
    id: response.id,
    name: response.name || 'Untitled service',
    preserveHost: Boolean(response.upstream?.preserve_host),
    requireClientCertificate: response.upstream?.identity === 'client_certificate',
    status: response.status === 'Disabled' ? 'Disabled' : 'Active',
    stickySession: toStickySession(response.upstream?.sticky_session),
    timeoutSecs: response.upstream?.timeout_secs ?? 0,
    upstreamUrl: response.upstream?.url ?? '',
  };
}

function toDiscoveryRequest(payload: ServiceFormInput) {
  if (!payload.discoveryEnabled) {
    return null;
  }

  return {
    kind: payload.discoveryKind,
    name: payload.discoveryName.trim(),
    refresh_secs: Number(payload.discoveryRefreshSecs),
  };
}

function toStickySessionRequest(payload: ServiceFormInput) {
  if (payload.stickySessionKind === 'None') {
    return null;
  }

  if (payload.stickySessionKind === 'Cookie' || payload.stickySessionKind === 'Header') {
    return { kind: payload.stickySessionKind, value: payload.stickySessionValue.trim() };
  }

  return { kind: payload.stickySessionKind };
}

function toRequest(payload: ServiceFormInput) {
  const audience = payload.expectedAudience.trim();

  return {
    health_check: toHealthCheckRequest(payload),
    name: payload.name,
    upstream: {
      backends: payload.additionalBackends.map((backend) => ({
        url: backend.url,
        weight: Number(backend.weight),
      })),
      discovery: toDiscoveryRequest(payload),
      expected_audience: audience ? { pinned: audience } : 'no_token_accepted',
      identity: payload.requireClientCertificate ? 'client_certificate' : 'token',
      preserve_host: payload.preserveHost,
      sticky_session: toStickySessionRequest(payload),
      timeout_secs: Number(payload.timeoutSecs),
      url: payload.upstreamUrl,
    },
  };
}

export async function getTenantServices(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantServicesParams,
): Promise<GatewayServiceList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<GatewayServiceListResponse>(endpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toGatewayService),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantService(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<GatewayService> {
  const { data } = await apiClient.get<GatewayServiceResponse>(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`,
  );
  return toGatewayService(data);
}

export async function createTenantService(
  orgSlug: string,
  tenantSlug: string,
  payload: ServiceFormInput,
): Promise<string> {
  const { data } = await apiClient.post<{ id: string }>(
    endpoint(orgSlug, tenantSlug),
    toRequest(payload),
  );
  return data.id;
}

export async function updateTenantService(
  orgSlug: string,
  tenantSlug: string,
  id: string,
  payload: ServiceFormInput,
): Promise<void> {
  await apiClient.patch(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`,
    toRequest(payload),
  );
}

function toAppSignInRequest(payload: AppSignInFormInput) {
  if (!payload.enabled) {
    return {
      accepts_app_sign_in_of: payload.acceptsAppSignInOf || null,
      app_sign_in: null,
      delivery: payload.acceptsAppSignInOf ? toDeliveryRequest(payload) : null,
    };
  }

  const paths = Object.fromEntries(
    SIGN_IN_ADDRESS_KEYS.map((key) => [key, payload.paths[key].trim() || null]),
  );

  return {
    accepts_app_sign_in_of: null,
    app_sign_in: {
      after_sign_in: payload.afterSignIn.trim() || null,
      hosts: payload.hosts,
      paths,
      prefix: payload.prefix.trim() || null,
      signed_out_browsers: payload.signedOutBrowsers,
    },
  };
}

function toDeliveryRequest(payload: AppSignInFormInput) {
  if (payload.deliveryKind === 'own_cookie') {
    return { hosts: payload.cookieHosts, kind: 'own_cookie' };
  }
  return { kind: payload.deliveryKind };
}

/// Turns a service's app sign-in on, changes it or turns it off.
export async function updateServiceAppSignIn(
  orgSlug: string,
  tenantSlug: string,
  id: string,
  payload: AppSignInFormInput,
): Promise<void> {
  await apiClient.put(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}/app-sign-in`,
    toAppSignInRequest(payload),
  );
}

export async function deleteTenantService(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<void> {
  await apiClient.delete(`${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`);
}
