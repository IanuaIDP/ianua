'use client';

import { useEffect } from 'react';

import { useAuthStore } from '@/store/auth-store';

export function TenantSuspendedCookieConsumer() {
  useEffect(() => {
    useAuthStore.getState().logout();

    void fetch('/api/tenant-suspended/consume', {
      cache: 'no-store',
      method: 'POST',
    });
  }, []);

  return null;
}
