import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type {
  AuditExport,
  AuditExportStatus,
  AuditLogEntry,
  AuditLogList,
  AuditLogSortDirection,
  AuditLogSortField,
} from '@/types/audit-log';
import { formatBackendDateTime } from '@/utils/date';
import { notAvailable } from '@/utils/not-available';

type ActedThroughResponse = {
  as_user_id?: string | null;
  execution_id?: string | null;
  impersonation_id?: string | null;
  kind: string;
  operator_id?: string | null;
};

export type AuditLogEntryResponse = {
  acted_through?: ActedThroughResponse | null;
  actor: string;
  details?: Record<string, unknown> | null;
  event_type: string;
  id: string;
  ip_address?: string | null;
  occurred_at: string;
  target_id?: string | null;
  tenant_name: string | null;
  tenant_slug: string | null;
};

type AuditLogResponse = {
  items: AuditLogEntryResponse[];
  limit: number;
  next_cursor: string | null;
};

export type GetAuditLogParams = {
  after?: string;
  before?: string;
  eventType?: string;
  limit?: number;
  search?: string;
  since?: string;
  sortDirection?: AuditLogSortDirection;
  sortField?: AuditLogSortField;
};

function getAuditLogEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/audit-log`;
}

function getAuditLogParams(params?: GetAuditLogParams) {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);
  const eventType = params?.eventType ?? (params?.search?.trim() || undefined);

  return {
    after: params?.after,
    before: params?.before,
    event_type: eventType,
    limit: params?.limit,
    since: params?.since,
    sort,
  };
}

async function fetchAuditLogResponse(orgSlug: string, params?: GetAuditLogParams) {
  return getList<AuditLogResponse>(getAuditLogEndpoint(orgSlug), {
    params: getAuditLogParams(params),
  });
}

function getEventScope(response: AuditLogEntryResponse) {
  return response.tenant_name ?? 'Organization';
}

function parseActor(actor: string): { email?: string; name: string } {
  const match = actor.match(/^(.*?)\s*\(([^()]+)\)\s*$/);

  if (!match) {
    return { name: actor.trim() };
  }

  return { email: match[2].trim(), name: match[1].trim() };
}

function toAuditLogEntry(response: AuditLogEntryResponse): AuditLogEntry {
  const { email: actorEmail, name: actorName } = parseActor(response.actor);

  return {
    actedThrough: response.acted_through?.kind ?? undefined,
    actor: actorName,
    actorEmail,
    dateTime: formatBackendDateTime(response.occurred_at),
    details:
      response.details && Object.keys(response.details).length > 0 ? response.details : undefined,
    event: response.event_type,
    eventScope: getEventScope(response),
    id: response.id,
    ip: response.ip_address ?? notAvailable(),
    tenantSlug: response.tenant_slug ?? undefined,
  };
}

export async function getAuditLog(
  orgSlug: string,
  params?: GetAuditLogParams,
): Promise<AuditLogList> {
  const response = await fetchAuditLogResponse(orgSlug, {
    ...params,
    limit: params?.limit ?? 20,
  });

  return {
    items: response.items.map(toAuditLogEntry),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

type AuditExportAcceptedResponse = {
  id: string;
};

type AuditExportResponse = {
  download_url?: string | null;
  id: string;
  status: AuditExportStatus;
};

type StartAuditExportRequest = {
  after?: string;
  before?: string;
  event_type?: string;
  format: 'csv';
};

export type StartAuditExportParams = {
  before?: string;
  eventType?: string;
  since?: string;
};

/** Asks for the whole log matching these filters, written by the worker as one file. */
export async function startAuditLogExport(orgSlug: string, params: StartAuditExportParams) {
  const response = await apiClient.post<AuditExportAcceptedResponse>(
    `${getAuditLogEndpoint(orgSlug)}/exports`,
    {
      after: params.since,
      before: params.before,
      event_type: params.eventType,
      format: 'csv',
    } satisfies StartAuditExportRequest,
  );

  return response.data.id;
}

export async function getAuditLogExport(orgSlug: string, exportId: string): Promise<AuditExport> {
  const response = await apiClient.get<AuditExportResponse>(
    `${getAuditLogEndpoint(orgSlug)}/exports/${encodeURIComponent(exportId)}`,
  );

  return { downloadUrl: response.data.download_url ?? undefined, status: response.data.status };
}

const EXPORT_POLL_MS = 2000;
const EXPORT_POLL_ATTEMPTS = 150;

/** Waits for the worker to write the export, and answers its one-time download link. */
export async function waitForAuditLogExport(orgSlug: string, exportId: string) {
  for (let attempt = 0; attempt < EXPORT_POLL_ATTEMPTS; attempt += 1) {
    const state = await getAuditLogExport(orgSlug, exportId);

    if (state.status === 'ready' && state.downloadUrl) {
      return state.downloadUrl;
    }

    if (state.status !== 'pending') {
      throw new Error(state.status);
    }

    await new Promise((resolve) => setTimeout(resolve, EXPORT_POLL_MS));
  }

  throw new Error('timed out');
}
