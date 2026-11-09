'use client';

import { useParams, usePathname } from 'next/navigation';

import { useAuthStore } from '@/store/auth-store';
import { getTenantRouteContext } from '@/utils/dashboard-routes';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useTenantRouteParams() {
  const params = useParams();
  const pathname = usePathname();
  const sessionOrganizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const routeTenantContext = getTenantRouteContext(pathname);
  const orgSlug =
    routeTenantContext?.orgSlug ?? getParamValue(params.orgSlug) ?? sessionOrganizationSlug;
  const tenantSlug = decodeURIComponent(getParamValue(params.tenantSlug) ?? 'tenant');
  const isTenantView = Boolean(routeTenantContext);

  return {
    isTenantView,
    orgSlug,
    tenantSlug,
  };
}
