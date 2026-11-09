import { apiClient } from '@/lib/api/client';
import { getById, getList } from '@/lib/api/crud';
import { ALL_SIGNAL_TYPES_VALUE } from '@/constants/stream';
import type { StreamFormInput } from '@/schemas/stream-schemas';
import type {
  DeliveryMethod,
  DeliveryStatus,
  SecuritySignalType,
  Stream,
  StreamAction,
  StreamDelivery,
  StreamDeliveryList,
  StreamList,
  StreamStatus,
} from '@/types/stream';
import { formatBackendDate, formatBackendDateTime } from '@/utils/date';

type StreamResponse = {
  consecutive_failures: number;
  created_at: string;
  delivery_method: string;
  endpoint: string;
  id: string;
  sends_authorization?: boolean;
  signal_types?: string[] | null;
  status: string;
  updated_at: string;
  verification?: string | null;
};

type RegisterStreamResponse = {
  id: string;
  receiver_key: string;
};

type StreamListResponse = {
  items: StreamResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantStreamsParams = {
  after?: string;
  limit?: number;
  status?: StreamStatus;
};

type StreamDeliveryResponse = {
  attempt_number: number;
  attempted_at: string;
  duration_ms: number;
  id: string;
  response_status?: number | null;
  signal_id: string;
  signal_type: string;
  status: string;
  stream_id: string;
};

type StreamDeliveryListResponse = {
  items: StreamDeliveryResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetStreamDeliveriesParams = {
  after?: string;
  limit?: number;
};

type UpsertStreamRequest = {
  delivery_method: DeliveryMethod;
  endpoint: string;
  signal_types: string[];
};

const SECURITY_SIGNAL_TYPES = new Set<SecuritySignalType>([
  'SessionRevoked',
  'SessionSuspended',
  'CredentialChanged',
  'AccountLocked',
  'AccountDisabled',
  'PermissionsChanged',
  'DeviceCompromised',
  'TokenCompromised',
  'RiskLevelChanged',
  'AssuranceChanged',
  'CredentialCompromised',
  'IdentifierChanged',
  'AccountPurged',
]);

function toDeliveryMethod(value: string): DeliveryMethod {
  return value === 'Poll' ? 'Poll' : 'Push';
}

function toStreamStatus(value: string): StreamStatus {
  if (value === 'Paused' || value === 'Disabled') {
    return value;
  }

  return 'Active';
}

function toSignalTypes(values?: string[] | null): SecuritySignalType[] {
  return (values ?? []).filter((value): value is SecuritySignalType =>
    SECURITY_SIGNAL_TYPES.has(value as SecuritySignalType),
  );
}

const DELIVERY_STATUSES = new Set<DeliveryStatus>([
  'Success',
  'Failed',
  'Timeout',
  'Unreachable',
  'Queued',
]);

function toDeliveryStatus(value: string): DeliveryStatus {
  return DELIVERY_STATUSES.has(value as DeliveryStatus) ? (value as DeliveryStatus) : 'Failed';
}

function toStreamDelivery(response: StreamDeliveryResponse): StreamDelivery {
  return {
    attemptNumber: response.attempt_number ?? 0,
    attemptedAt: formatBackendDateTime(response.attempted_at),
    durationMs: response.duration_ms ?? 0,
    id: response.id,
    responseStatus: response.response_status ?? null,
    signalId: response.signal_id,
    signalType: (toSignalTypes([response.signal_type])[0] ??
      response.signal_type) as SecuritySignalType,
    status: toDeliveryStatus(response.status),
    streamId: response.stream_id,
  };
}

function toStream(response: StreamResponse): Stream {
  return {
    consecutiveFailures: response.consecutive_failures ?? 0,
    created: formatBackendDate(response.created_at),
    deliveryMethod: toDeliveryMethod(response.delivery_method),
    endpoint: response.endpoint,
    id: response.id,
    signalTypes: toSignalTypes(response.signal_types),
    status: toStreamStatus(response.status),
    updated: formatBackendDate(response.updated_at),
    verification: response.verification ?? null,
  };
}

function toUpsertStreamRequest(payload: StreamFormInput): UpsertStreamRequest {
  return {
    delivery_method: payload.deliveryMethod,
    endpoint: payload.endpoint.trim(),
    signal_types: payload.signalTypes.filter((value) => value !== ALL_SIGNAL_TYPES_VALUE),
  };
}

function getTenantStreamsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/streams`;
}

export async function getTenantStreams(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantStreamsParams,
): Promise<StreamList> {
  const response = await getList<StreamListResponse>(
    getTenantStreamsEndpoint(orgSlug, tenantSlug),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        status: params?.status,
      },
    },
  );

  return {
    items: response.items.map(toStream),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
): Promise<Stream> {
  const response = await getById<StreamResponse>(
    getTenantStreamsEndpoint(orgSlug, tenantSlug),
    streamId,
  );

  return toStream(response);
}

function getStreamDeliveriesEndpoint(orgSlug: string, tenantSlug: string, streamId: string) {
  return `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}/deliveries`;
}

export async function getStreamDeliveries(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
  params?: GetStreamDeliveriesParams,
): Promise<StreamDeliveryList> {
  const response = await getList<StreamDeliveryListResponse>(
    getStreamDeliveriesEndpoint(orgSlug, tenantSlug, streamId),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
      },
    },
  );

  return {
    items: response.items.map(toStreamDelivery),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

/** Registers the stream and returns its receiver key, shown this once. */
export async function registerTenantStream(
  orgSlug: string,
  tenantSlug: string,
  payload: StreamFormInput,
): Promise<string> {
  const response = await apiClient.post<RegisterStreamResponse>(
    getTenantStreamsEndpoint(orgSlug, tenantSlug),
    toUpsertStreamRequest(payload) satisfies UpsertStreamRequest,
  );

  return response.data.receiver_key;
}

export async function updateTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
  payload: StreamFormInput,
): Promise<void> {
  await apiClient.patch(
    `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}`,
    toUpsertStreamRequest(payload) satisfies UpsertStreamRequest,
  );
}

export async function deleteTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}`,
  );
}

export async function pauseTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}/pause`,
  );
}

export async function resumeTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}/resume`,
  );
}

export async function disableTenantStream(
  orgSlug: string,
  tenantSlug: string,
  streamId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantStreamsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(streamId)}/disable`,
  );
}

export async function executeStreamAction(
  orgSlug: string,
  tenantSlug: string,
  stream: Stream,
  action: StreamAction,
): Promise<void> {
  if (action === 'Pause') {
    await pauseTenantStream(orgSlug, tenantSlug, stream.id);
    return;
  }

  if (action === 'Resume') {
    await resumeTenantStream(orgSlug, tenantSlug, stream.id);
    return;
  }

  if (action === 'Disable') {
    await disableTenantStream(orgSlug, tenantSlug, stream.id);
    return;
  }

  if (action === 'Delete') {
    await deleteTenantStream(orgSlug, tenantSlug, stream.id);
  }
}
