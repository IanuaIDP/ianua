'use client';

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';

import { getTenantMetrics } from '@/lib/api';
import { getMetricsWindowParams, type MetricsWindow } from '@/lib/overview/metrics';

export function useTenantMetrics(
  orgSlug: string | undefined,
  tenantSlug: string,
  window: MetricsWindow = 'daily',
  options?: { enabled?: boolean },
) {
  const metricsParams = useMemo(() => getMetricsWindowParams(window), [window]);
  const enabled = options?.enabled ?? true;

  return useQuery({
    enabled: Boolean(orgSlug && tenantSlug) && enabled,
    queryFn: () => {
      if (!orgSlug) {
        throw new Error('Organization is missing from your session. Please log in again.');
      }

      return getTenantMetrics(orgSlug, tenantSlug, metricsParams);
    },
    queryKey: [
      'tenant-metrics',
      orgSlug,
      tenantSlug,
      window,
      metricsParams.since,
      metricsParams.until,
    ],
  });
}
