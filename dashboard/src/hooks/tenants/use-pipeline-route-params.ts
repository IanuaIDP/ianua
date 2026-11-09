'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function usePipelineRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const pipelineId = decodeURIComponent(getParamValue(params.pipelineId) ?? '');

  return {
    isTenantView,
    orgSlug,
    pipelineId,
    tenantSlug,
  };
}
