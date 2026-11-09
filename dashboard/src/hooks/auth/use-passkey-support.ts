'use client';

import { useEffect, useState } from 'react';

import { isPasskeySupported } from '@/lib/auth/webauthn';

/**
 * Feature-detects platform WebAuthn support so passkey UI can be hidden (never
 * disabled — no dead buttons) on browsers/devices that can't do it.
 */
export function usePasskeySupport() {
  const [isSupported, setIsSupported] = useState(false);

  useEffect(() => {
    let isMounted = true;

    isPasskeySupported().then((supported) => {
      if (isMounted) {
        setIsSupported(supported);
      }
    });

    return () => {
      isMounted = false;
    };
  }, []);

  return isSupported;
}
