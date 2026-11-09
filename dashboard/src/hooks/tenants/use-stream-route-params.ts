'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useStreamRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const streamId = decodeURIComponent(getParamValue(params.streamId) ?? '');

  return {
    isTenantView,
    orgSlug,
    streamId,
    tenantSlug,
  };
}
