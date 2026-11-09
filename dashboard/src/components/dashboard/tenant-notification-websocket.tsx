'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { useNotification } from '@/components/ui/notifications';
import { REALTIME_NOTIFICATION_RECONNECT_DELAYS } from '@/constants/notification';
import { getTenantPath } from '@/utils/dashboard-routes';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  getNotificationToast,
  getTenantNotificationWebSocketUrl,
  isDomainEvent,
  parseNotificationMessage,
} from '@/lib/notifications/realtime-notifications';
import {
  invalidateTenantDomainQueries,
  invalidateTenantNotificationQueries,
} from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';

export function TenantNotificationWebSocket() {
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const accessToken = useAuthStore((state) => state.accessToken);
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const reconnectAttemptRef = useRef(0);
  const hasOpenedRef = useRef(false);
  const webSocketUrl = useMemo(() => {
    if (!accessToken || !orgSlug || !tenantSlug) {
      return null;
    }

    return getTenantNotificationWebSocketUrl(orgSlug, tenantSlug, accessToken);
  }, [accessToken, orgSlug, tenantSlug]);
  const notificationsPath = orgSlug
    ? `${getTenantPath(orgSlug, tenantSlug)}/notifications`
    : undefined;

  useEffect(() => {
    if (!webSocketUrl || !orgSlug || !tenantSlug) {
      return;
    }

    let isDisposed = false;
    let reconnectTimeout: number | null = null;
    let socket: WebSocket | null = null;
    const notificationWebSocketUrl = webSocketUrl;

    function scheduleReconnect() {
      if (isDisposed) {
        return;
      }

      const delay =
        REALTIME_NOTIFICATION_RECONNECT_DELAYS[
          Math.min(reconnectAttemptRef.current, REALTIME_NOTIFICATION_RECONNECT_DELAYS.length - 1)
        ];
      reconnectAttemptRef.current += 1;
      reconnectTimeout = window.setTimeout(connect, delay);
    }

    function connect() {
      socket = new WebSocket(notificationWebSocketUrl);

      socket.addEventListener('open', () => {
        hasOpenedRef.current = true;
        reconnectAttemptRef.current = 0;
      });

      socket.addEventListener('message', (event) => {
        void invalidateTenantNotificationQueries(queryClient, orgSlug, tenantSlug);

        const payload = parseNotificationMessage(event.data);

        if (isDomainEvent(payload)) {
          void invalidateTenantDomainQueries(queryClient, orgSlug, tenantSlug);
        }

        const notificationToast = getNotificationToast(payload);

        if (notificationToast) {
          showNotification({
            ...notificationToast,
            actionHref: notificationsPath,
            autoDismiss: true,
            type: 'default',
          });
        }
      });

      socket.addEventListener('close', (event) => {
        if (!isDisposed && event.code !== 1000) {
          scheduleReconnect();
        }
      });

      socket.addEventListener('error', () => {
        if (!hasOpenedRef.current) {
          return;
        }

        socket?.close();
      });
    }

    connect();

    return () => {
      isDisposed = true;
      hasOpenedRef.current = false;

      if (reconnectTimeout) {
        window.clearTimeout(reconnectTimeout);
      }

      socket?.close(1000, 'Dashboard unmounted');
    };
  }, [notificationsPath, orgSlug, queryClient, showNotification, tenantSlug, webSocketUrl]);

  return null;
}
