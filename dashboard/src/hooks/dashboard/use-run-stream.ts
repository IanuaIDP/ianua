'use client';

import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { getWorkflowRunWebSocketUrl } from '@/lib/notifications/realtime-notifications';
import { REALTIME_NOTIFICATION_RECONNECT_DELAYS } from '@/constants/notification';
import { useAuthStore } from '@/store/auth-store';

const CLOSE_NO_LONGER_ALLOWED = 1008;
const ATTEMPTS_BEFORE_GIVING_UP = 3;

/**
 * Reads the run again whenever the platform says it changed. A frame carries
 * no data and a push that fails is only logged, so the page also polls and
 * never depends on seeing one.
 */
export function useRunStream(
  orgSlug: string | undefined,
  tenantSlug: string,
  runId: string,
  isEnabled: boolean,
) {
  const queryClient = useQueryClient();
  const accessToken = useAuthStore((state) => state.accessToken);

  useEffect(() => {
    if (!isEnabled || !accessToken || !orgSlug) {
      return;
    }

    const url = getWorkflowRunWebSocketUrl(orgSlug, tenantSlug, runId, accessToken);

    if (!url) {
      return;
    }

    let isDisposed = false;
    let attempts = 0;
    let hasOpened = false;
    let reconnectTimeout: number | null = null;
    let socket: WebSocket | null = null;
    const streamUrl = url;

    function readAgain() {
      void queryClient.invalidateQueries({
        queryKey: ['workflow-run', orgSlug, tenantSlug, runId],
      });
    }

    function scheduleReconnect() {
      if (isDisposed || (!hasOpened && attempts >= ATTEMPTS_BEFORE_GIVING_UP)) {
        return;
      }

      const delay =
        REALTIME_NOTIFICATION_RECONNECT_DELAYS[
          Math.min(attempts, REALTIME_NOTIFICATION_RECONNECT_DELAYS.length - 1)
        ];

      attempts += 1;
      reconnectTimeout = window.setTimeout(connect, delay);
    }

    function connect() {
      socket = new WebSocket(streamUrl);
      socket.addEventListener('open', () => {
        hasOpened = true;
        attempts = 0;
      });
      socket.addEventListener('message', readAgain);
      socket.addEventListener('close', (event) => {
        if (!isDisposed && event.code !== CLOSE_NO_LONGER_ALLOWED && event.code !== 1000) {
          scheduleReconnect();
        }
      });
    }

    connect();

    return () => {
      isDisposed = true;

      if (reconnectTimeout) {
        window.clearTimeout(reconnectTimeout);
      }

      socket?.close(1000, 'Dashboard unmounted');
    };
  }, [accessToken, isEnabled, orgSlug, queryClient, runId, tenantSlug]);
}
