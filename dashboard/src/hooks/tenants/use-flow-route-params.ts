'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useFlowRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const flowId = decodeURIComponent(getParamValue(params.flowId) ?? '');

  return {
    flowId,
    isTenantView,
    orgSlug,
    tenantSlug,
  };
}
