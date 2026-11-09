import { apiClient } from '@/lib/api/client';

type AgentChannelResponse = {
  closed_at?: string | null;
  expires_at: string;
  id: string;
  max_class: string;
  open: boolean;
  opened_at: string;
  receiver_agent_id: string;
  scope: string;
  scope_kind: string;
  sender_agent_id: string;
};

type AgentChannelPage = {
  items: AgentChannelResponse[];
  next_cursor?: string | null;
};

export type AccountChannelStatus =
  'registering' | 'awaiting_key' | 'awaiting_token' | 'awaiting_confirmation' | 'live' | 'lapsed';

export type AccountChannel = {
  address: string;
  setup: 'registered' | 'pasted_key' | 'token_from_service';
  status: AccountChannelStatus;
};

export type AgentChannel = {
  expiresAt: string;
  id: string;
  isOpen: boolean;
  maxClass: string;
  openedAt: string;
  receiverAgentId: string;
  scope: string;
  scopeKind: string;
  senderAgentId: string;
};

export type OpenAgentChannelRequest = {
  lifetimeSeconds: number;
  maxClass: string;
  receiverAgentId: string;
  resource?: string;
  senderAgentId: string;
  topics?: string;
};

const CHANNELS_PAGE_SIZE = 100;

function getTenantEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

function getAccountChannelEndpoint(orgSlug: string, tenantSlug: string, accountId: string) {
  return `${getTenantEndpoint(orgSlug, tenantSlug)}/workflows/accounts/${encodeURIComponent(accountId)}/event-channel`;
}

function toAgentChannel(response: AgentChannelResponse): AgentChannel {
  return {
    expiresAt: response.expires_at,
    id: response.id,
    isOpen: response.open,
    maxClass: response.max_class,
    openedAt: response.opened_at,
    receiverAgentId: response.receiver_agent_id,
    scope: response.scope,
    scopeKind: response.scope_kind,
    senderAgentId: response.sender_agent_id,
  };
}

export async function getAccountChannel(orgSlug: string, tenantSlug: string, accountId: string) {
  const { data } = await apiClient.get<AccountChannel>(
    getAccountChannelEndpoint(orgSlug, tenantSlug, accountId),
  );

  return data;
}

export async function setAccountChannelKey(
  orgSlug: string,
  tenantSlug: string,
  accountId: string,
  key: string,
) {
  const { data } = await apiClient.post<AccountChannel>(
    `${getAccountChannelEndpoint(orgSlug, tenantSlug, accountId)}/key`,
    { key },
  );

  return data;
}

export async function showAccountChannelToken(
  orgSlug: string,
  tenantSlug: string,
  accountId: string,
) {
  const { data } = await apiClient.post<{ token: string }>(
    `${getAccountChannelEndpoint(orgSlug, tenantSlug, accountId)}/token`,
  );

  return data.token;
}

export async function confirmAccountChannel(
  orgSlug: string,
  tenantSlug: string,
  accountId: string,
) {
  const { data } = await apiClient.post<AccountChannel>(
    `${getAccountChannelEndpoint(orgSlug, tenantSlug, accountId)}/confirm`,
  );

  return data;
}

/** Every channel between the tenant's agents, following each page to the end. */
export async function getAgentChannels(orgSlug: string, tenantSlug: string) {
  const channels: AgentChannel[] = [];
  let after: string | undefined;

  do {
    const { data } = await apiClient.get<AgentChannelPage>(
      `${getTenantEndpoint(orgSlug, tenantSlug)}/messaging/channels`,
      { params: { after, limit: CHANNELS_PAGE_SIZE } },
    );

    channels.push(...data.items.map(toAgentChannel));
    after = data.next_cursor ?? undefined;
  } while (after);

  return channels;
}

export async function openAgentChannel(
  orgSlug: string,
  tenantSlug: string,
  request: OpenAgentChannelRequest,
) {
  await apiClient.post(`${getTenantEndpoint(orgSlug, tenantSlug)}/messaging/channels`, {
    lifetime_seconds: request.lifetimeSeconds,
    max_class: request.maxClass,
    receiver_agent_id: request.receiverAgentId,
    resource: request.resource,
    sender_agent_id: request.senderAgentId,
    topics: request.topics,
  });
}

export async function closeAgentChannel(orgSlug: string, tenantSlug: string, channelId: string) {
  await apiClient.post(
    `${getTenantEndpoint(orgSlug, tenantSlug)}/messaging/channels/${encodeURIComponent(channelId)}/close`,
  );
}
