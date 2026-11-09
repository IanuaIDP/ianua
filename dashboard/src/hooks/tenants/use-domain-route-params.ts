'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useDomainRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const domainId = decodeURIComponent(getParamValue(params.domainId) ?? '');

  return {
    domainId,
    isTenantView,
    orgSlug,
    tenantSlug,
  };
}
