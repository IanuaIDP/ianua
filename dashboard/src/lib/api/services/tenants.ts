import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import { getRegionSlug } from '@/constants/cloud';
import type {
  CreateTenantInput,
  TenantResidencyInput,
  TenantSettingsGeneralInput,
} from '@/schemas/tenant-schemas';
import type {
  CloudProviderId,
  IsolationLevelId,
  ResidencyKind,
  TenantResidency,
} from '@/types/cloud-account';
import { formatBackendDate } from '@/utils/date';
import type {
  Tenant,
  TenantAction,
  TenantDetail,
  TenantList,
  TenantSortDirection,
  TenantSortField,
  TenantStatus,
} from '@/types/tenant';

type ResidencyResponse = {
  data_residency?: string | null;
  isolation?: IsolationLevelId | null;
  kind?: ResidencyKind | null;
  network?: string | null;
  network_pending?: boolean | null;
  provider?: CloudProviderId | null;
  region?: string | null;
};

export type TenantResponse = {
  contact_email: string;
  created_at?: string | null;
  deletable_from?: string | null;
  display_name: string;
  environment?: string | null;
  id: string;
  locale: string;
  login_url?: string | null;
  organization_id: string;
  primary_domain?: string | null;
  residency?: ResidencyResponse | null;
  slug: string;
  status: TenantStatus;
  timezone: string;
  updated_at: string;
};

type ResidencyRequest =
  | { isolation: IsolationLevelId; kind: 'platform'; region?: string }
  | {
      isolation: IsolationLevelId;
      kind: 'customer_cloud';
      network?: string;
      provider: CloudProviderId;
      region: string;
    }
  | { isolation: IsolationLevelId; kind: 'customer_database' };

function toResidencyRequest(residency: TenantResidencyInput): ResidencyRequest {
  if (residency.kind === 'customer_database') {
    return { isolation: residency.isolation, kind: residency.kind };
  }

  if (residency.kind === 'platform') {
    return {
      isolation: residency.isolation,
      kind: residency.kind,
      region: residency.region ? getRegionSlug(residency.region) : undefined,
    };
  }

  return {
    isolation: residency.isolation,
    kind: residency.kind,
    network: residency.network || undefined,
    provider: residency.provider ?? 'aws',
    region: getRegionSlug(residency.region ?? 'EuCentral1'),
  };
}

function toResidency(response?: ResidencyResponse | null): TenantResidency {
  return {
    dataResidency: response?.data_residency ?? undefined,
    isolation: response?.isolation ?? 'Shared',
    kind: response?.kind ?? 'platform',
    network: response?.network ?? undefined,
    networkPending: response?.network_pending ?? false,
    provider: response?.provider ?? undefined,
    region: response?.region ?? undefined,
  };
}

type TenantsResponse = {
  items: TenantResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantsParams = {
  after?: string;
  limit?: number;
  sortDirection?: TenantSortDirection;
  sortField?: TenantSortField;
  status?: TenantStatus;
};

type CreateTenantRequest = {
  contact_email: string;
  display_name: string;
  locale: string;
  residency: ResidencyRequest;
  slug: string;
  timezone: string;
};

type UpdateTenantSettingsRequest = {
  contact_email: string | null;
  display_name: string | null;
  locale: string | null;
  primary_domain: string | null;
  timezone: string | null;
};

function toTenant(response: TenantResponse): Tenant {
  return {
    created: formatBackendDate(response.created_at),
    deletableFrom: response.deletable_from ?? null,
    id: response.id,
    name: response.display_name,
    slug: response.slug,
    status: response.status,
  };
}

function toTenantDetail(response: TenantResponse): TenantDetail {
  return {
    contactEmail: response.contact_email,
    created: formatBackendDate(response.created_at),
    displayName: response.display_name,
    environment: response.environment ?? null,
    id: response.id,
    locale: response.locale,
    loginUrl: response.login_url ?? null,
    organizationId: response.organization_id,
    primaryDomain: response.primary_domain ?? null,
    residency: toResidency(response.residency),
    slug: response.slug,
    status: response.status,
    timezone: response.timezone,
    updated: formatBackendDate(response.updated_at),
  };
}

export async function getTenants(orgSlug: string, params?: GetTenantsParams): Promise<TenantList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<TenantsResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants`,
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
        status: params?.status,
      },
    },
  );

  return {
    items: response.items.map(toTenant),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function createTenant(orgSlug: string, payload: CreateTenantInput): Promise<Tenant> {
  const response = await createResource<TenantResponse, CreateTenantRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants`,
    {
      contact_email: payload.contactEmail,
      display_name: payload.displayName,
      locale: payload.locale,
      residency: toResidencyRequest(payload.residency),
      slug: payload.slug,
      timezone: payload.timezone,
    },
  );

  return toTenant(response);
}

function getTenantEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

export async function getTenant(orgSlug: string, tenantSlug: string): Promise<TenantDetail> {
  const response = await apiClient.get<TenantResponse>(getTenantEndpoint(orgSlug, tenantSlug));

  return toTenantDetail(response.data);
}

export type UpdateTenantSettingsPayload = TenantSettingsGeneralInput & {
  primaryDomain: string | null;
};

export async function updateTenantSettings(
  orgSlug: string,
  tenantSlug: string,
  payload: UpdateTenantSettingsPayload,
): Promise<TenantDetail> {
  await apiClient.patch<unknown>(getTenantEndpoint(orgSlug, tenantSlug), {
    contact_email: payload.contactEmail.trim() || null,
    display_name: payload.displayName.trim() || null,
    locale: payload.locale.trim() || null,
    primary_domain: payload.primaryDomain,
    timezone: payload.timezone.trim() || null,
  } satisfies UpdateTenantSettingsRequest);

  return getTenant(orgSlug, tenantSlug);
}

async function postTenantAction(orgSlug: string, tenantSlug: string, actionPath: string) {
  const response = await apiClient.post<TenantResponse>(
    `${getTenantEndpoint(orgSlug, tenantSlug)}/${actionPath}`,
  );

  return toTenant(response.data);
}

export async function suspendTenant(orgSlug: string, tenantSlug: string) {
  return postTenantAction(orgSlug, tenantSlug, 'suspend');
}

export async function reactivateTenant(orgSlug: string, tenantSlug: string) {
  return postTenantAction(orgSlug, tenantSlug, 'reactivate');
}

export async function archiveTenant(orgSlug: string, tenantSlug: string) {
  return postTenantAction(orgSlug, tenantSlug, 'archive');
}

export async function deleteTenant(orgSlug: string, tenantSlug: string) {
  await apiClient.delete(getTenantEndpoint(orgSlug, tenantSlug));
}

export function executeTenantAction(orgSlug: string, tenant: Tenant, action: TenantAction) {
  if (action === 'Suspend') {
    return suspendTenant(orgSlug, tenant.slug);
  }

  if (action === 'Restore Access') {
    return reactivateTenant(orgSlug, tenant.slug);
  }

  if (action === 'Archive') {
    return archiveTenant(orgSlug, tenant.slug);
  }

  return deleteTenant(orgSlug, tenant.slug);
}
