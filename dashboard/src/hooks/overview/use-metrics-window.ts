'use client';

import { useMemo, useState } from 'react';

import { getMetricsWindowParams, type MetricsWindow } from '@/lib/overview/metrics';

export function useMetricsWindow(initialWindow: MetricsWindow = 'monthly') {
  const [metricsWindow, setMetricsWindow] = useState<MetricsWindow>(initialWindow);
  const metricsParams = useMemo(() => getMetricsWindowParams(metricsWindow), [metricsWindow]);

  function handleMetricsWindowChange(window: MetricsWindow) {
    if (window === metricsWindow) {
      return;
    }

    setMetricsWindow(window);
  }

  return { handleMetricsWindowChange, metricsParams, metricsWindow };
}
