'use client';

import { useQuery } from '@tanstack/react-query';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getCurrentTenantUser, getOrganizationMe } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';

/**
 * The signed-in person as the API names them in `acting_for` and `owner`:
 * `tenant_user:<id>` in a tenant session, `org_user:<id>` in an organization
 * one. `null` until it is read.
 */
export function useWorkflowCaller() {
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const isTenantSession = useAuthStore((state) => state.access === null);
  const { data: tenantUser } = useQuery({
    enabled: isTenantSession && Boolean(orgSlug && tenantSlug),
    queryFn: () => getCurrentTenantUser(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-current-user', orgSlug, tenantSlug],
  });
  const { data: orgUser } = useQuery({
    enabled: !isTenantSession && Boolean(orgSlug),
    queryFn: () => getOrganizationMe(orgSlug ?? ''),
    queryKey: ['organization-me', orgSlug],
  });

  if (isTenantSession) {
    return tenantUser ? `tenant_user:${tenantUser.id}` : null;
  }

  return orgUser ? `org_user:${orgUser.id}` : null;
}
