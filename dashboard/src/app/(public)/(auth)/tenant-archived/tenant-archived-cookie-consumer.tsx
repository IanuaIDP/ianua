'use client';

import { useEffect } from 'react';

import { useAuthStore } from '@/store/auth-store';

export function TenantArchivedCookieConsumer() {
  useEffect(() => {
    useAuthStore.getState().logout();

    void fetch('/api/tenant-archived/consume', {
      cache: 'no-store',
      method: 'POST',
    });
  }, []);

  return null;
}
