import type { QueryClient } from '@tanstack/react-query';

export function notificationCountQueryKey(organizationSlug?: string | null) {
  return organizationSlug
    ? ['notifications', organizationSlug, 'count']
    : ['notifications', 'count'];
}

export function notificationListQueryKey(organizationSlug?: string | null, filter?: string | null) {
  return organizationSlug
    ? ['notifications', organizationSlug, 'list', filter].filter(Boolean)
    : ['notifications', 'list', filter].filter(Boolean);
}

export function invalidateAuditLogQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
) {
  return Promise.all([
    queryClient.invalidateQueries({
      queryKey: organizationSlug ? ['audit-log', organizationSlug] : ['audit-log'],
    }),
    queryClient.invalidateQueries({
      queryKey: organizationSlug ? ['recent-activity', organizationSlug] : ['recent-activity'],
    }),
    invalidateNotificationQueries(queryClient, organizationSlug),
  ]);
}

export function invalidateNotificationQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: organizationSlug ? ['notifications', organizationSlug] : ['notifications'],
  });
}

export function invalidateNotificationCountQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: notificationCountQueryKey(organizationSlug),
  });
}

export function invalidateNotificationListQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: organizationSlug
      ? ['notifications', organizationSlug, 'list']
      : ['notifications', 'list'],
  });
}

export function tenantNotificationCountQueryKey(
  organizationSlug?: string | null,
  tenantSlug?: string | null,
) {
  return ['tenant-notifications', organizationSlug, tenantSlug, 'count'];
}

export function tenantNotificationListQueryKey(
  organizationSlug?: string | null,
  tenantSlug?: string | null,
  filter?: string | null,
) {
  return ['tenant-notifications', organizationSlug, tenantSlug, 'list', filter].filter(Boolean);
}

export function invalidateTenantNotificationQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
  tenantSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: ['tenant-notifications', organizationSlug, tenantSlug],
  });
}

export function invalidateTenantNotificationListQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
  tenantSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: ['tenant-notifications', organizationSlug, tenantSlug, 'list'],
  });
}

export function invalidateTenantDomainQueries(
  queryClient: QueryClient,
  organizationSlug?: string | null,
  tenantSlug?: string | null,
) {
  return queryClient.invalidateQueries({
    queryKey: ['tenant-domains', organizationSlug, tenantSlug],
  });
}
