'use client';

import { useParams } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';

function getParamValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export function useWorkflowRouteParams() {
  const params = useParams();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const workflowId = decodeURIComponent(getParamValue(params.workflowId) ?? '');

  return { isTenantView, orgSlug, tenantSlug, workflowId: workflowId || null };
}
