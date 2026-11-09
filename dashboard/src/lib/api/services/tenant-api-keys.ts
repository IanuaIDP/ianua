import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { CreateTenantApiKeyInput } from '@/schemas/tenant-api-key-schemas';
import type {
  CreatedTenantApiKey,
  TenantApiKey,
  TenantApiKeyList,
  TenantApiKeySortDirection,
  TenantApiKeySortField,
  TenantApiKeyStatus,
} from '@/types/tenant-api-key';
import { formatBackendDate, parseBackendTimestamp } from '@/utils/date';

type TenantApiKeyResponse = {
  created_at?: string | null;
  expires_at?: string | null;
  id: string;
  last_used_at?: string | null;
  last_used_ip?: string | null;
  name?: string | null;
  paused_at?: string | null;
  raw_key?: string | null;
  scopes?: string[] | null;
  token?: string | null;
};

type TenantApiKeyListResponse = {
  items: TenantApiKeyResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantApiKeysParams = {
  after?: string;
  limit?: number;
  sortDirection?: TenantApiKeySortDirection;
  sortField?: TenantApiKeySortField;
};

type CreateTenantApiKeyRequest = {
  expires_at?: string;
  name: string;
  scopes: string[];
};

function toTenantApiKeyStatus(response: TenantApiKeyResponse): TenantApiKeyStatus {
  if (response.paused_at) {
    return 'Paused';
  }

  const endsAt = parseBackendTimestamp(response.expires_at);

  return endsAt && endsAt <= new Date() ? 'Expired' : 'Active';
}

/** The last moment of `day` where the person is: a key lasts through the day they picked. */
function toEndOfDay(day: string) {
  return new Date(`${day}T23:59:59`).toISOString();
}

function toTenantApiKey(response: TenantApiKeyResponse): TenantApiKey {
  return {
    created: formatBackendDate(response.created_at),
    ends: response.expires_at ? formatBackendDate(response.expires_at) : null,
    id: response.id,
    lastUsed: formatBackendDate(response.last_used_at),
    lastUsedIp: response.last_used_ip ?? null,
    name: response.name || 'API key',
    scopes: response.scopes ?? [],
    status: toTenantApiKeyStatus(response),
  };
}

function getTenantApiKeysEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/oauth/api-keys`;
}

export async function getTenantApiKeys(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantApiKeysParams,
): Promise<TenantApiKeyList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<TenantApiKeyListResponse>(
    getTenantApiKeysEndpoint(orgSlug, tenantSlug),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
      },
    },
  );

  return {
    items: response.items.map(toTenantApiKey),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function createTenantApiKey(
  orgSlug: string,
  tenantSlug: string,
  payload: CreateTenantApiKeyInput,
): Promise<CreatedTenantApiKey> {
  const response = await apiClient.post<TenantApiKeyResponse>(
    getTenantApiKeysEndpoint(orgSlug, tenantSlug),
    {
      expires_at: payload.endsOn ? toEndOfDay(payload.endsOn) : undefined,
      name: payload.name,
      scopes: payload.scopes,
    } satisfies CreateTenantApiKeyRequest,
  );

  return {
    id: response.data.id,
    key: response.data.raw_key ?? response.data.token ?? '',
  };
}

export async function pauseTenantApiKey(
  orgSlug: string,
  tenantSlug: string,
  apiKeyId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantApiKeysEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(apiKeyId)}/pause`,
  );
}

export async function resumeTenantApiKey(
  orgSlug: string,
  tenantSlug: string,
  apiKeyId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantApiKeysEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(apiKeyId)}/resume`,
  );
}

export async function revokeTenantApiKey(
  orgSlug: string,
  tenantSlug: string,
  apiKeyId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantApiKeysEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(apiKeyId)}/revoke`,
  );
}
