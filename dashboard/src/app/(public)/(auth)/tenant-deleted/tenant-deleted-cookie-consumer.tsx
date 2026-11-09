'use client';

import { useEffect } from 'react';

import { useAuthStore } from '@/store/auth-store';

export function TenantDeletedCookieConsumer() {
  useEffect(() => {
    useAuthStore.getState().logout();

    void fetch('/api/tenant-deleted/consume', {
      cache: 'no-store',
      method: 'POST',
    });
  }, []);

  return null;
}
