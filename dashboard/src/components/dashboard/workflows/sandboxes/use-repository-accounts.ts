'use client';

import { useQuery } from '@tanstack/react-query';

import { useWorkflowCaller } from '@/hooks/dashboard/use-workflow-caller';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getWorkflowAccounts } from '@/lib/api';

const REPOSITORY_INTEGRATIONS = new Set(['github', 'gitlab']);
const ACCOUNTS_PAGE = 100;

/** GitHub and GitLab accounts the signed-in person owns or may manage. */
export function useRepositoryAccounts() {
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const caller = useWorkflowCaller();
  const canManage = hasPermission('Workflows', 'ConnectAccounts');
  const { data, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getWorkflowAccounts(orgSlug ?? '', tenantSlug, { limit: ACCOUNTS_PAGE }),
    queryKey: ['workflow-accounts', orgSlug, tenantSlug, 'repositories'],
  });
  const accounts = (data?.items ?? []).filter(
    (account) =>
      REPOSITORY_INTEGRATIONS.has(account.integration) &&
      account.status !== 'disabled' &&
      (canManage || account.owner === caller),
  );

  return { accounts, isLoading };
}
