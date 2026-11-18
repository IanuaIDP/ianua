'use client';

import { useEffect } from 'react';

import { useAnalyticsConsentStore } from '@/store/analytics-consent-store';

/** Reads the stored choice in the browser and tells the footer that analytics exist. */
export function AnalyticsRegistration() {
  const register = useAnalyticsConsentStore((state) => state.register);

  useEffect(() => {
    register();
  }, [register]);

  return null;
}
