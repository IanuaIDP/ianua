'use client';

import { useEffect, useState } from 'react';

import { isSignupOpen } from '@/lib/api/services/signup';

/** Whether this deployment takes signups; false until known. */
export function useSignupOpen(): boolean {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    let isCancelled = false;

    isSignupOpen()
      .then((open) => {
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
  }, []);

  return isOpen;
}
