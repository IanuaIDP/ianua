import { RealtimeNotificationPayload } from '@/types/notification';

function toWebSocketProtocol(protocol: string) {
  return protocol === 'https:' ? 'wss:' : 'ws:';
}

function joinUrlPath(basePath: string, endpointPath: string) {
  return `${basePath.replace(/\/$/, '')}/${endpointPath.replace(/^\//, '')}`;
}

export function getNotificationWebSocketUrl(orgSlug: string, accessToken: string) {
  if (typeof window === 'undefined') {
    return null;
  }

  const endpoint = `/organizations/${encodeURIComponent(orgSlug)}/ws/notifications`;
  const configuredWsUrl = process.env.NEXT_PUBLIC_WS_URL;
  const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL || '/api';
  const baseUrl = configuredWsUrl || configuredApiUrl;
  const url = new URL(joinUrlPath(baseUrl, endpoint), window.location.origin);

  url.protocol = toWebSocketProtocol(url.protocol);
  url.searchParams.set('token', accessToken);

  return url.toString();
}

export function getTenantNotificationWebSocketUrl(
  orgSlug: string,
  tenantSlug: string,
  accessToken: string,
) {
  if (typeof window === 'undefined') {
    return null;
  }

  const endpoint = `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/ws/notifications`;
  const configuredWsUrl = process.env.NEXT_PUBLIC_WS_URL;
  const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL || '/api';
  const baseUrl = configuredWsUrl || configuredApiUrl;
  const url = new URL(joinUrlPath(baseUrl, endpoint), window.location.origin);

  url.protocol = toWebSocketProtocol(url.protocol);
  url.searchParams.set('token', accessToken);

  return url.toString();
}

/** The address of one workflow run's live stream. Frames only say that it changed. */
export function getWorkflowRunWebSocketUrl(
  orgSlug: string,
  tenantSlug: string,
  runId: string,
  accessToken: string,
) {
  if (typeof window === 'undefined') {
    return null;
  }

  const endpoint = `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/ws/workflows/executions/${encodeURIComponent(runId)}`;
  const configuredWsUrl = process.env.NEXT_PUBLIC_WS_URL;
  const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL || '/api';
  const baseUrl = configuredWsUrl || configuredApiUrl;
  const url = new URL(joinUrlPath(baseUrl, endpoint), window.location.origin);

  url.protocol = toWebSocketProtocol(url.protocol);
  url.searchParams.set('token', accessToken);

  return url.toString();
}

/**
 * Events that change a domain's row without anyone touching the page.
 *
 * Both waits land in a background worker: verification whenever DNS finally
 * propagates, and the certificate some minutes after that. Neither is the
 * result of a request this tab made, so the table has no other reason to
 * re-read itself.
 */
const DOMAIN_EVENT_TYPES = new Set([
  'tenant.domain_registered',
  'tenant.domain_verified',
  'tenant.domain_removed',
  'tenant.domain_tls_provisioned',
]);

/** Whether a realtime frame reports a change to a domain. */
export function isDomainEvent(payload: RealtimeNotificationPayload | null) {
  return typeof payload?.event_type === 'string' && DOMAIN_EVENT_TYPES.has(payload.event_type);
}

export function parseNotificationMessage(data: unknown): RealtimeNotificationPayload | null {
  if (typeof data !== 'string') {
    return null;
  }

  try {
    const parsed = JSON.parse(data) as RealtimeNotificationPayload;

    return parsed.notification ?? parsed.data ?? parsed;
  } catch {
    return { message: data };
  }
}

export function getNotificationToast(payload: RealtimeNotificationPayload | null) {
  if (!payload) {
    return null;
  }

  const title = typeof payload.title === 'string' ? payload.title.trim() : '';
  const body =
    typeof payload.body === 'string'
      ? payload.body.trim()
      : typeof payload.message === 'string'
        ? payload.message.trim()
        : '';

  const message = title || body;

  if (!message) {
    return null;
  }

  return {
    body: body && body !== title ? body : undefined,
    message,
    title: title || undefined,
  };
}
