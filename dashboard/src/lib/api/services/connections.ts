import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import type { AddConnectionInput } from '@/schemas/connection-schemas';
import type {
  Connection,
  ConnectionAction,
  ConnectionList,
  ConnectionSortDirection,
  ConnectionSortField,
  ConnectionStatus,
} from '@/types/connection';
import { formatBackendDate } from '@/utils/date';
import { notAvailable } from '@/utils/not-available';

type ConnectionResponse = {
  allowed_domains?: string[] | null;
  assurance_trust?: 'Untrusted' | 'Trusted' | null;
  attribute_mapping?: Record<string, string> | null;
  created_at?: string | null;
  domain_hint?: string | null;
  email_trust?: 'Unverified' | 'Authoritative' | null;
  group_mapping?: Record<string, unknown> | null;
  id: string;
  jit_provisioning?: boolean | null;
  saml?: Record<string, unknown> | null;
  protocol?: string | null;
  provider_name?: string | null;
  status?: string | null;
};

type ConnectionListResponse = {
  items: ConnectionResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantConnectionsParams = {
  after?: string;
  limit?: number;
  sortDirection?: ConnectionSortDirection;
  sortField?: ConnectionSortField;
};

type EnableScimResponse = {
  bearer_token?: string | null;
  token?: string | null;
};

type ScimSettingsBody = {
  auto_activate: boolean;
  deactivate_on_remove: boolean;
  default_role_id: string | null;
};

type ScimStatusResponse = {
  configured: boolean;
  enabled: boolean;
  last_sync_at: string | null;
  scim_path: string;
  settings?: ScimSettingsBody;
};

export type ScimSettings = {
  autoActivate: boolean;
  deactivateOnRemove: boolean;
  defaultRoleId: string | null;
};

export type ScimStatus = {
  configured: boolean;
  enabled: boolean;
  lastSyncAt: string | null;
  scimPath: string;
  settings: ScimSettings | null;
};

type SamlConnectionConfig = {
  certificate: string;
  entity_id: string;
  name_id_format: string;
  sso_url: string;
};

type OidcConnectionConfig = {
  authorization_url: string;
  client_id: string;
  encrypted_client_secret: string;
  issuer: string;
  scopes: string[];
  token_url: string;
};

type CreateConnectionRequest = {
  allowed_domains: string[];
  config:
    | {
        Saml: SamlConnectionConfig;
      }
    | {
        Oidc: OidcConnectionConfig;
      };
  provider_name: string;
};

function parseScopes(value?: string): string[] {
  return (value ?? '')
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

const protocolLabels: Record<string, string> = {
  saml: 'SAML 2.0',
  oidc: 'OIDC',
};

function toConnectionStatus(value?: string | null): ConnectionStatus {
  return value?.toLowerCase() === 'active' ? 'Active' : 'Disabled';
}

function toProtocolLabel(value?: string | null) {
  if (!value) {
    return notAvailable();
  }

  return protocolLabels[value.toLowerCase()] ?? value;
}

function toConnection(response: ConnectionResponse): Connection {
  return {
    allowedDomains: response.allowed_domains ?? [],
    assuranceTrust: response.assurance_trust ?? null,
    attributeMapping: response.attribute_mapping ?? {},
    created: formatBackendDate(response.created_at),
    domainHint: response.domain_hint ?? null,
    emailTrust: response.email_trust ?? null,
    groupMapping: response.group_mapping ?? null,
    id: response.id,
    isJitProvisioningEnabled: Boolean(response.jit_provisioning),
    saml: response.saml ?? null,
    name: response.provider_name || 'Untitled connection',
    protocol: toProtocolLabel(response.protocol),
    status: toConnectionStatus(response.status),
  };
}

function getTenantConnectionsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/federation/connections`;
}

function getTenantScimEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/federation/scim`;
}

export async function getTenantConnections(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantConnectionsParams,
): Promise<ConnectionList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<ConnectionListResponse>(
    getTenantConnectionsEndpoint(orgSlug, tenantSlug),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
      },
    },
  );

  return {
    items: response.items.map(toConnection),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function createTenantConnection(
  orgSlug: string,
  tenantSlug: string,
  payload: AddConnectionInput,
): Promise<Connection> {
  const config: CreateConnectionRequest['config'] =
    payload.protocol === 'SAML'
      ? {
          Saml: {
            certificate: payload.certificate ?? '',
            entity_id: payload.entityId ?? '',
            name_id_format: payload.nameIdFormat ?? '',
            sso_url: payload.ssoUrl ?? '',
          },
        }
      : {
          Oidc: {
            authorization_url: payload.authorizationUrl ?? '',
            client_id: payload.clientId ?? '',
            encrypted_client_secret: payload.clientSecret ?? '',
            issuer: payload.issuer ?? '',
            scopes: parseScopes(payload.scopes),
            token_url: payload.tokenUrl ?? '',
          },
        };

  const response = await createResource<ConnectionResponse, CreateConnectionRequest>(
    getTenantConnectionsEndpoint(orgSlug, tenantSlug),
    {
      allowed_domains: payload.allowedDomains,
      config,
      provider_name: payload.providerName,
    },
  );

  return toConnection(response);
}

export async function deleteTenantConnection(
  orgSlug: string,
  tenantSlug: string,
  connectionId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantConnectionsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(connectionId)}`,
  );
}

export async function activateTenantConnection(
  orgSlug: string,
  tenantSlug: string,
  connectionId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantConnectionsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(connectionId)}/activate`,
  );
}

export async function disableTenantConnection(
  orgSlug: string,
  tenantSlug: string,
  connectionId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantConnectionsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(connectionId)}/disable`,
  );
}

export async function executeConnectionAction(
  orgSlug: string,
  tenantSlug: string,
  connection: Connection,
  action: ConnectionAction,
): Promise<void> {
  if (action === 'Activate') {
    await activateTenantConnection(orgSlug, tenantSlug, connection.id);
    return;
  }

  if (action === 'Disable') {
    await disableTenantConnection(orgSlug, tenantSlug, connection.id);
    return;
  }

  if (action === 'Delete') {
    await deleteTenantConnection(orgSlug, tenantSlug, connection.id);
  }
}

export async function enableTenantScim(orgSlug: string, tenantSlug: string): Promise<string> {
  const response = await apiClient.post<EnableScimResponse>(
    getTenantScimEndpoint(orgSlug, tenantSlug),
  );

  return response.data.bearer_token ?? response.data.token ?? '';
}

export async function disableTenantScim(orgSlug: string, tenantSlug: string): Promise<void> {
  await apiClient.delete(getTenantScimEndpoint(orgSlug, tenantSlug));
}

export async function getTenantScimStatus(
  orgSlug: string,
  tenantSlug: string,
): Promise<ScimStatus> {
  const response = await apiClient.get<ScimStatusResponse>(
    getTenantScimEndpoint(orgSlug, tenantSlug),
  );
  const { settings } = response.data;

  return {
    configured: response.data.configured,
    enabled: response.data.enabled,
    lastSyncAt: response.data.last_sync_at,
    scimPath: response.data.scim_path,
    settings: settings
      ? {
          autoActivate: settings.auto_activate,
          deactivateOnRemove: settings.deactivate_on_remove,
          defaultRoleId: settings.default_role_id,
        }
      : null,
  };
}

export async function updateTenantScimSettings(
  orgSlug: string,
  tenantSlug: string,
  settings: ScimSettings,
): Promise<void> {
  await apiClient.put(`${getTenantScimEndpoint(orgSlug, tenantSlug)}/settings`, {
    auto_activate: settings.autoActivate,
    deactivate_on_remove: settings.deactivateOnRemove,
    default_role_id: settings.defaultRoleId,
  } satisfies ScimSettingsBody);
}

export async function rotateTenantScimToken(orgSlug: string, tenantSlug: string): Promise<string> {
  const response = await apiClient.post<EnableScimResponse>(
    `${getTenantScimEndpoint(orgSlug, tenantSlug)}/rotate-token`,
    { bearer_token: '' },
  );

  return response.data.bearer_token ?? response.data.token ?? '';
}
