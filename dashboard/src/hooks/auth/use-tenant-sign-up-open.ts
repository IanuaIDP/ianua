'use client';

import { useEffect, useState } from 'react';

import { getTenantSignUpRules } from '@/lib/api/services/auth';

/** Whether the tenant takes sign-ups; false until known, and for org sign-in. */
export function useTenantSignUpOpen(orgSlug?: string, tenantSlug?: string): boolean {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    if (!orgSlug || !tenantSlug) {
      return;
    }

    let isCancelled = false;

    getTenantSignUpRules({ orgSlug, tenantSlug })
      .then(({ open }) => {
        if (!isCancelled) {
          setIsOpen(open);
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setIsOpen(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [orgSlug, tenantSlug]);

  return isOpen;
}
