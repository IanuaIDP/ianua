'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useAgentRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const agentId = decodeURIComponent(getParamValue(params.agentId) ?? '');

  return {
    agentId,
    isTenantView,
    orgSlug,
    tenantSlug,
  };
}
