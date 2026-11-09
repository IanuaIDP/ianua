import { apiClient } from '@/lib/api/client';

export type NotificationEventType = Record<string, string> | string;

export type NotificationResponse = {
  body?: string | null;
  category?: string | null;
  created_at?: string | null;
  event_type?: NotificationEventType | null;
  id?: string | null;
  read?: boolean | null;
  resource_id?: string | null;
  severity?: string | null;
  title?: string | null;
};

export type NotificationItem = {
  body: string;
  category: string;
  createdAt: string;
  eventType: string;
  id: string;
  isRead: boolean;
  resourceId: string;
  severity: string;
  title: string;
};

type NotificationsResponse = {
  items: NotificationResponse[];
  limit: number;
  next_cursor: string | null;
};

type NotificationsCountResponse =
  | number
  | {
      count?: number | null;
      total?: number | null;
      unread_count?: number | null;
      unreadCount?: number | null;
    };

type GetNotificationsParams = {
  after?: string;
  limit?: number;
  unreadOnly?: boolean;
};

export type NotificationList = {
  items: NotificationItem[];
  limit: number;
  nextCursor: string | null;
};

function formatEventType(value?: NotificationEventType | null) {
  if (!value) {
    return '';
  }

  if (typeof value === 'string') {
    return value;
  }

  const [scope, event] = Object.entries(value)[0] ?? [];

  return [scope, event].filter(Boolean).join(': ');
}

function toNotificationCount(response: NotificationsCountResponse): number {
  if (typeof response === 'number') {
    return Math.max(0, response);
  }

  if (typeof response.count === 'number') {
    return Math.max(0, response.count);
  }

  if (typeof response.unread_count === 'number') {
    return Math.max(0, response.unread_count);
  }

  if (typeof response.unreadCount === 'number') {
    return Math.max(0, response.unreadCount);
  }

  if (typeof response.total === 'number') {
    return Math.max(0, response.total);
  }

  return 0;
}

function toNotificationItem(response: NotificationResponse): NotificationItem {
  const title = response.title?.trim() || formatEventType(response.event_type) || 'Notification';
  const body = response.body?.trim() || 'No details provided.';
  const id = response.id ?? response.resource_id ?? `${title}-${body}-${response.created_at ?? ''}`;

  return {
    body,
    category: response.category ?? '',
    createdAt: response.created_at ?? '',
    eventType: formatEventType(response.event_type),
    id,
    isRead: response.read ?? false,
    resourceId: response.resource_id ?? '',
    severity: response.severity ?? '',
    title,
  };
}

function toNotificationList(response: NotificationsResponse): NotificationList {
  return {
    items: response.items.map(toNotificationItem),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

function getNotificationsEndpoint(orgSlug: string) {
  return `/api/organizations/${encodeURIComponent(orgSlug)}/notifications`;
}

function getTenantNotificationsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/api/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/notifications`;
}

function getSameOriginEndpoint(endpoint: string) {
  return typeof window === 'undefined' ? endpoint : `${window.location.origin}${endpoint}`;
}

export async function getNotificationsCount(orgSlug: string): Promise<number> {
  const endpoint = `/api/organizations/${encodeURIComponent(orgSlug)}/notifications/unread-count`;
  const response = await apiClient.get<NotificationsCountResponse>(getSameOriginEndpoint(endpoint));

  return toNotificationCount(response.data);
}

export async function getNotifications(
  orgSlug: string,
  params?: GetNotificationsParams,
): Promise<NotificationList> {
  const response = await apiClient.get<NotificationsResponse>(
    getSameOriginEndpoint(getNotificationsEndpoint(orgSlug)),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        unread_only: params?.unreadOnly || undefined,
      },
    },
  );

  return toNotificationList(response.data);
}

export async function markNotificationAsRead(
  orgSlug: string,
  notificationId: string,
): Promise<void> {
  await apiClient.post<unknown>(
    getSameOriginEndpoint(
      `${getNotificationsEndpoint(orgSlug)}/${encodeURIComponent(notificationId)}/read`,
    ),
  );
}

export async function markAllNotificationsAsRead(orgSlug: string): Promise<void> {
  await apiClient.post<unknown>(
    getSameOriginEndpoint(`${getNotificationsEndpoint(orgSlug)}/read-all`),
  );
}

export async function getTenantNotificationsCount(
  orgSlug: string,
  tenantSlug: string,
): Promise<number> {
  const endpoint = `/api/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/notifications/unread-count`;
  const response = await apiClient.get<NotificationsCountResponse>(getSameOriginEndpoint(endpoint));

  return toNotificationCount(response.data);
}

export async function getTenantNotifications(
  orgSlug: string,
  tenantSlug: string,
  params?: GetNotificationsParams,
): Promise<NotificationList> {
  const response = await apiClient.get<NotificationsResponse>(
    getSameOriginEndpoint(getTenantNotificationsEndpoint(orgSlug, tenantSlug)),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        unread_only: params?.unreadOnly || undefined,
      },
    },
  );

  return toNotificationList(response.data);
}

export async function markTenantNotificationAsRead(
  orgSlug: string,
  tenantSlug: string,
  notificationId: string,
): Promise<void> {
  await apiClient.post<unknown>(
    getSameOriginEndpoint(
      `${getTenantNotificationsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
        notificationId,
      )}/read`,
    ),
  );
}

export async function markAllTenantNotificationsAsRead(
  orgSlug: string,
  tenantSlug: string,
): Promise<void> {
  await apiClient.post<unknown>(
    getSameOriginEndpoint(`${getTenantNotificationsEndpoint(orgSlug, tenantSlug)}/read-all`),
  );
}
