import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { CreateApiKeyInput } from '@/schemas/settings-schemas';
import type {
  ApiKey,
  ApiKeyList,
  ApiKeySortDirection,
  ApiKeySortField,
  ApiKeyStatus,
  CreatedApiKey,
} from '@/types/api-key';
import { formatBackendDate, parseBackendTimestamp } from '@/utils/date';
import { notAvailable } from '@/utils/not-available';

export type ApiKeyResponse = {
  created_at?: string | null;
  created_by?: string | null;
  expires_at?: string | null;
  id?: string | null;
  key?: string | null;
  key_prefix?: string | null;
  last_used_at?: string | null;
  name?: string | null;
  raw_key?: string | null;
  revoked?: boolean | null;
  status?: ApiKeyStatus | null;
  token?: string | null;
};

type ApiKeysResponse = {
  items: ApiKeyResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetApiKeysParams = {
  after?: string;
  limit?: number;
  sortDirection?: ApiKeySortDirection;
  sortField?: ApiKeySortField;
};

type CreateApiKeyRequest = {
  expires_at: string | null;
  name: string;
  scopes: string[];
};

function getApiKeysEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/api-keys`;
}

function maskApiKey(value?: string | null) {
  if (!value) {
    return notAvailable();
  }

  if (value.length <= 12) {
    return value;
  }

  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function toApiKeyStatus(response: ApiKeyResponse): ApiKeyStatus {
  if (response.revoked) {
    return 'Revoked';
  }

  const endsAt = parseBackendTimestamp(response.expires_at);

  return endsAt && endsAt <= new Date() ? 'Expired' : (response.status ?? 'Active');
}

function toApiKey(response: ApiKeyResponse): ApiKey {
  const id = response.id ?? response.key_prefix ?? response.key ?? response.token ?? '';

  return {
    created: formatBackendDate(response.created_at),
    createdBy: response.created_by ?? null,
    expires: response.expires_at ? formatBackendDate(response.expires_at) : null,
    id,
    key: maskApiKey(response.key ?? response.token ?? response.key_prefix),
    lastUsed: formatBackendDate(response.last_used_at),
    name: response.name ?? 'API key',
    status: toApiKeyStatus(response),
  };
}

export async function getApiKeys(orgSlug: string, params?: GetApiKeysParams): Promise<ApiKeyList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<ApiKeysResponse>(getApiKeysEndpoint(orgSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toApiKey),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function revokeApiKey(orgSlug: string, apiKeyId: string): Promise<void> {
  await apiClient.post(`${getApiKeysEndpoint(orgSlug)}/${encodeURIComponent(apiKeyId)}/revoke`);
}

export async function createApiKey(
  orgSlug: string,
  payload: CreateApiKeyInput,
): Promise<CreatedApiKey> {
  const response = await apiClient.post<ApiKeyResponse>(getApiKeysEndpoint(orgSlug), {
    expires_at: payload.expiresAt ? new Date(`${payload.expiresAt}T23:59:59`).toISOString() : null,
    name: payload.name,
    scopes: payload.scopes,
  } satisfies CreateApiKeyRequest);

  return {
    id: response.data.id ?? undefined,
    key: response.data.raw_key ?? response.data.key ?? response.data.token ?? '',
    keyPrefix: response.data.key_prefix ?? undefined,
  };
}
