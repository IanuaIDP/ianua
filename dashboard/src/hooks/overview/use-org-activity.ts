'use client';

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';

import { getOrgActivity } from '@/lib/api';

function formatDateParam(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');

  return `${year}-${month}-${day}`;
}

export function useOrgActivity(orgSlug: string | undefined, enabled = true) {
  const { from, to } = useMemo(() => {
    const toDate = new Date();
    const fromDate = new Date(toDate);
    fromDate.setMonth(fromDate.getMonth() - 3);

    return {
      from: formatDateParam(fromDate),
      to: formatDateParam(toDate),
    };
  }, []);

  return useQuery({
    enabled: Boolean(orgSlug) && enabled,
    queryFn: () => {
      if (!orgSlug) {
        throw new Error('Organization is missing from your session. Please log in again.');
      }

      return getOrgActivity(orgSlug, { from, to });
    },
    queryKey: ['org-activity', orgSlug, from, to],
  });
}
