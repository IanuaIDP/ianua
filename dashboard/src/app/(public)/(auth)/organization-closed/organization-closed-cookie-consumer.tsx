'use client';

import { useEffect } from 'react';

import { useAuthStore } from '@/store/auth-store';
import { useOrganizationStore } from '@/store/organization-store';

export function OrganizationClosedCookieConsumer() {
  useEffect(() => {
    useAuthStore.getState().logout();
    useOrganizationStore.getState().clearOrganization();

    void fetch('/api/organization-closed/consume', {
      cache: 'no-store',
      method: 'POST',
    });
  }, []);

  return null;
}
