'use client';

import { useEffect } from 'react';

import { useAuthStore } from '@/store/auth-store';
import { useOrganizationStore } from '@/store/organization-store';

export function OrganizationSuspendedCookieConsumer() {
  useEffect(() => {
    useAuthStore.getState().logout();
    useOrganizationStore.getState().clearOrganization();

    void fetch('/api/organization-suspended/consume', {
      cache: 'no-store',
      method: 'POST',
    });
  }, []);

  return null;
}
