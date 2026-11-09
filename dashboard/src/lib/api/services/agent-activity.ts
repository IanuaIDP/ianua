import { getList } from '@/lib/api/crud';
import type { AuditLogEntryResponse } from '@/lib/api/services/audit-log';
import type {
  AgentActivityEvent,
  AgentActivityList,
  AgentActivitySortDirection,
  AgentActivitySortField,
} from '@/types/activity';

export type GetAgentActivityParams = {
  after?: string;
  before?: string;
  eventType?: string;
  limit?: number;
  sortDirection?: AgentActivitySortDirection;
  sortField?: AgentActivitySortField;
};

type AgentActivityResponse = {
  items: AuditLogEntryResponse[];
  limit: number;
  next_cursor: string | null;
};

function getAgentActivityEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/activity`;
}

function buildActivitySort(field?: AgentActivitySortField, direction?: AgentActivitySortDirection) {
  if (!field || !direction) {
    return undefined;
  }

  return `${direction === 'desc' ? '-' : ''}${field}`;
}

function toAgentActivityEvent(response: AuditLogEntryResponse): AgentActivityEvent {
  return {
    actor: response.actor,
    details:
      response.details && Object.keys(response.details).length > 0 ? response.details : undefined,
    eventType: response.event_type,
    id: response.id,
    occurredAt: response.occurred_at,
    targetId: response.target_id ?? undefined,
  };
}

export async function getAgentActivity(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  params?: GetAgentActivityParams,
): Promise<AgentActivityList> {
  const response = await getList<AgentActivityResponse>(
    getAgentActivityEndpoint(orgSlug, tenantSlug, agentId),
    {
      params: {
        after: params?.after,
        before: params?.before,
        event_type: params?.eventType,
        limit: params?.limit ?? 50,
        sort: buildActivitySort(params?.sortField, params?.sortDirection),
      },
    },
  );

  return {
    items: response.items.map(toAgentActivityEvent),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}
