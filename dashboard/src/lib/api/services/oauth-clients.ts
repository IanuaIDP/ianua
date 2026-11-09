import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type {
  CreatedOAuthClient,
  OAuthClient,
  OAuthClientList,
  OAuthClientSortDirection,
  OAuthClientSortField,
  OAuthClientStatus,
} from '@/types/oauth-client';
import { formatBackendDate } from '@/utils/date';

type OAuthClientResponse = {
  client_id?: string | null;
  created_at?: string | null;
  grant_types?: string[] | null;
  id: string;
  name?: string | null;
  redirect_uris?: string[] | null;
  scopes?: string[] | null;
  settings?: Record<string, unknown> | null;
  status?: string | null;
};

type OAuthClientListResponse = {
  items: OAuthClientResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantOAuthClientsParams = {
  after?: string;
  limit?: number;
  sortDirection?: OAuthClientSortDirection;
  sortField?: OAuthClientSortField;
};

type CreateOAuthClientResponse = {
  client_id?: string | null;
  client_secret?: string | null;
  id?: string | null;
};

type CreateOAuthClientRequest = {
  grant_types: string[];
  name: string;
  redirect_uris: string[];
  scopes: string[];
};

type UpdateOAuthClientRequest = {
  name: string | null;
  redirect_uris: string[] | null;
  scopes: string[] | null;
};

export type UpdateOAuthClientPayload = {
  name: string;
  redirectUris: string[] | null;
};

export function parseRedirectUris(value?: string): string[] {
  return (value ?? '')
    .split('\n')
    .map((uri) => uri.trim())
    .filter(Boolean);
}

function toOAuthClientStatus(value?: string | null): OAuthClientStatus {
  return value === 'Revoked' ? 'Revoked' : 'Active';
}

function toOAuthClient(response: OAuthClientResponse): OAuthClient {
  return {
    clientId: response.client_id ?? '',
    created: formatBackendDate(response.created_at),
    grantTypes: response.grant_types ?? [],
    id: response.id,
    name: response.name || 'Untitled client',
    redirectUris: response.redirect_uris ?? [],
    scopes: response.scopes ?? [],
    settings: response.settings ?? {},
    status: toOAuthClientStatus(response.status),
  };
}

function getTenantOAuthClientsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/oauth/clients`;
}

export async function getTenantOAuthClients(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantOAuthClientsParams,
): Promise<OAuthClientList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<OAuthClientListResponse>(
    getTenantOAuthClientsEndpoint(orgSlug, tenantSlug),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
      },
    },
  );

  return {
    items: response.items.map(toOAuthClient),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function createTenantOAuthClient(
  orgSlug: string,
  tenantSlug: string,
  payload: { name: string; redirectUris: string[] },
): Promise<CreatedOAuthClient> {
  const response = await apiClient.post<CreateOAuthClientResponse>(
    getTenantOAuthClientsEndpoint(orgSlug, tenantSlug),
    {
      grant_types: ['AuthorizationCode'],
      name: payload.name,
      redirect_uris: payload.redirectUris,
      scopes: [],
    } satisfies CreateOAuthClientRequest,
  );

  return {
    clientId: response.data.client_id ?? response.data.id ?? '',
    clientSecret: response.data.client_secret ?? '',
  };
}

export async function updateTenantOAuthClient(
  orgSlug: string,
  tenantSlug: string,
  clientId: string,
  payload: UpdateOAuthClientPayload,
): Promise<void> {
  await apiClient.patch(
    `${getTenantOAuthClientsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(clientId)}`,
    {
      name: payload.name,
      redirect_uris: payload.redirectUris,
      scopes: null,
    } satisfies UpdateOAuthClientRequest,
  );
}

export async function revokeTenantOAuthClient(
  orgSlug: string,
  tenantSlug: string,
  clientId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantOAuthClientsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(clientId)}/revoke`,
  );
}

type RotatedOAuthClientSecretResponse = {
  client_secret: string;
};

/** Replaces the client's secret and returns the new one, shown this once. */
export async function rotateTenantOAuthClientSecret(
  orgSlug: string,
  tenantSlug: string,
  clientId: string,
): Promise<string> {
  const response = await apiClient.post<RotatedOAuthClientSecretResponse>(
    `${getTenantOAuthClientsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(clientId)}/rotate-secret`,
    {},
  );

  return response.data.client_secret;
}
