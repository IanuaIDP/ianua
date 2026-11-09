'use client';

import { useEffect, useState } from 'react';

import { getApiErrorMessage } from '@/lib/api';

export function useResendCooldown() {
  const [isResending, setIsResending] = useState(false);
  const [cooldownSeconds, setCooldownSeconds] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (cooldownSeconds <= 0) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setCooldownSeconds((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => window.clearTimeout(timeoutId);
  }, [cooldownSeconds]);

  async function resend(action: () => Promise<number>, fallbackErrorMessage: string) {
    if (cooldownSeconds > 0) {
      return;
    }

    setError(null);

    try {
      setIsResending(true);
      const retryAfterSeconds = await action();
      setCooldownSeconds(retryAfterSeconds);
    } catch (caughtError) {
      setError(getApiErrorMessage(caughtError, fallbackErrorMessage));
    } finally {
      setIsResending(false);
    }
  }

  return { cooldownSeconds, error, isResending, resend };
}
