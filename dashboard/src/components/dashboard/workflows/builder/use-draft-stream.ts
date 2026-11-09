'use client';

import { useEffect, useRef } from 'react';

import { REALTIME_NOTIFICATION_RECONNECT_DELAYS } from '@/constants/notification';
import { useAuthStore } from '@/store/auth-store';

const POLL_MS = 15_000;

type DraftStreamOptions = {
  enabled: boolean;
  onChanged: () => void;
  orgSlug: string | undefined;
  tenantSlug: string;
  workflowId: string | null;
};

function getDraftStreamUrl(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string,
  accessToken: string,
) {
  const endpoint = `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/ws/workflows/${encodeURIComponent(workflowId)}/draft`;
  const base = (
    process.env.NEXT_PUBLIC_WS_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    '/api'
  ).replace(/\/$/, '');
  const url = new URL(`${base}${endpoint}`, window.location.origin);

  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('token', accessToken);

  return url.toString();
}

/** Tells the builder when someone changed the draft. A frame carries no data, only "read again". */
export function useDraftStream({
  enabled,
  onChanged,
  orgSlug,
  tenantSlug,
  workflowId,
}: DraftStreamOptions) {
  const accessToken = useAuthStore((state) => state.accessToken);
  const handler = useRef(onChanged);

  useEffect(() => {
    handler.current = onChanged;
  });

  useEffect(() => {
    if (!enabled || !accessToken || !orgSlug || !workflowId) {
      return;
    }

    let isDisposed = false;
    let attempt = 0;
    let retryTimer: number | undefined;
    let socket: WebSocket | null = null;
    const pollTimer = window.setInterval(() => handler.current(), POLL_MS);
    const url = getDraftStreamUrl(orgSlug, tenantSlug, workflowId, accessToken);

    function connect() {
      socket = new WebSocket(url);

      socket.addEventListener('open', () => {
        attempt = 0;
      });

      socket.addEventListener('message', (event) => {
        if (typeof event.data === 'string' && event.data.includes('draft_changed')) {
          handler.current();
        }
      });

      socket.addEventListener('close', (event) => {
        if (isDisposed || event.code === 1000 || event.code === 1008) {
          return;
        }

        const delay =
          REALTIME_NOTIFICATION_RECONNECT_DELAYS[
            Math.min(attempt, REALTIME_NOTIFICATION_RECONNECT_DELAYS.length - 1)
          ];

        attempt += 1;
        retryTimer = window.setTimeout(connect, delay);
      });
    }

    connect();

    return () => {
      isDisposed = true;
      window.clearInterval(pollTimer);
      window.clearTimeout(retryTimer);
      socket?.close(1000, 'Builder closed');
    };
  }, [accessToken, enabled, orgSlug, tenantSlug, workflowId]);
}
