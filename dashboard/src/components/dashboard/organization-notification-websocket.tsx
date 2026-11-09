'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { useNotification } from '@/components/ui/notifications';
import {
  NOTIFICATIONS_PATH,
  REALTIME_NOTIFICATION_RECONNECT_DELAYS,
} from '@/constants/notification';
import {
  getNotificationToast,
  getNotificationWebSocketUrl,
  parseNotificationMessage,
} from '@/lib/notifications/realtime-notifications';
import { invalidateNotificationQueries } from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';

export function OrganizationNotificationWebSocket() {
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const accessToken = useAuthStore((state) => state.accessToken);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const reconnectAttemptRef = useRef(0);
  const hasOpenedRef = useRef(false);
  const webSocketUrl = useMemo(() => {
    if (!accessToken || !organizationSlug) {
      return null;
    }

    return getNotificationWebSocketUrl(organizationSlug, accessToken);
  }, [accessToken, organizationSlug]);

  useEffect(() => {
    if (!webSocketUrl || !organizationSlug) {
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
        void invalidateNotificationQueries(queryClient, organizationSlug);

        const notificationToast = getNotificationToast(parseNotificationMessage(event.data));

        if (notificationToast) {
          showNotification({
            ...notificationToast,
            actionHref: NOTIFICATIONS_PATH,
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
  }, [organizationSlug, queryClient, showNotification, webSocketUrl]);

  return null;
}
