'use client';

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';

import { getOrgMetrics } from '@/lib/api';
import { getMetricsWindowParams, type MetricsWindow } from '@/lib/overview/metrics';

export function useOrgMetrics(orgSlug: string | undefined, window: MetricsWindow = 'daily') {
  const metricsParams = useMemo(() => getMetricsWindowParams(window), [window]);

  return useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => {
      if (!orgSlug) {
        throw new Error('Organization is missing from your session. Please log in again.');
      }

      return getOrgMetrics(orgSlug, metricsParams);
    },
    queryKey: ['org-metrics', orgSlug, window, metricsParams.since, metricsParams.until],
  });
}
