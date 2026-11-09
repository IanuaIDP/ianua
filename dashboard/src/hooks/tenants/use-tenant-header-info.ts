'use client';

import { useQuery } from '@tanstack/react-query';

import { useTenantMetrics } from '@/hooks/tenants/use-tenant-metrics';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { getTenants } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import type { TenantStatus } from '@/types/tenant';

/**
 * Name and status for the tenant breadcrumb. Metrics are the richest source
 * but need Metrics permission, so org sessions fall back to the tenant list
 * (which every org user can read) and the access list for the name.
 */
export function useTenantHeaderInfo(orgSlug: string | undefined, tenantSlug: string) {
  const { hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const accessTenants = useAuthStore((state) => state.access?.tenants);
  const isOrgSession = useAuthStore((state) => state.access !== null);
  const canViewMetrics = !isLoadingPermissions && hasPermission('Metrics', 'View');

  const { data: metrics } = useTenantMetrics(orgSlug, tenantSlug, undefined, {
    enabled: canViewMetrics,
  });
  const { data: tenantList } = useQuery({
    enabled: Boolean(orgSlug) && isOrgSession && !canViewMetrics && !isLoadingPermissions,
    queryFn: () => getTenants(orgSlug ?? '', { limit: 100 }),
    queryKey: ['tenants', orgSlug, 'header-lookup'],
    staleTime: 60_000,
  });
  const listedTenant = tenantList?.items.find((tenant) => tenant.slug === tenantSlug);

  const tenantStatus =
    (canViewMetrics ? (metrics?.status as TenantStatus | undefined) : undefined) ??
    listedTenant?.status;
  const companyDisplayName =
    (canViewMetrics ? metrics?.company.displayName : undefined) ??
    listedTenant?.name ??
    accessTenants?.find((tenant) => tenant.slug === tenantSlug)?.displayName ??
    tenantSlug;

  return { companyDisplayName, tenantStatus };
}
