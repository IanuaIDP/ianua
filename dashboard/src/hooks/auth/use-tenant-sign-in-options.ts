'use client';

import { useEffect, useState } from 'react';

import { getTenantSignInOptions, type SignInOptions } from '@/lib/api/services/auth';

const NOTHING_OFFERED: SignInOptions = { connections: [], magicLink: false, passkey: false };

/** What a tenant's sign-in page offers; nothing until known, and for org sign-in. */
export function useTenantSignInOptions(orgSlug?: string, tenantSlug?: string): SignInOptions {
  const [options, setOptions] = useState<SignInOptions>(NOTHING_OFFERED);

  useEffect(() => {
    if (!orgSlug || !tenantSlug) {
      return;
    }

    let isCancelled = false;

    getTenantSignInOptions({ orgSlug, tenantSlug })
      .then((loaded) => {
        if (!isCancelled) {
          setOptions(loaded);
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setOptions(NOTHING_OFFERED);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [orgSlug, tenantSlug]);

  return options;
}
