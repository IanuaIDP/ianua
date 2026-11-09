'use client';

import { useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getWorkflowApprovalPath } from '@/utils/dashboard-routes';

/** The approval page has one home, the address Slack links to: this tree sends people there. */
export default function ManagementApprovalRedirect() {
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const router = useRouter();
  const params = useParams<{ runId: string; step: string }>();

  useEffect(() => {
    if (orgSlug) {
      router.replace(
        getWorkflowApprovalPath(
          orgSlug,
          tenantSlug,
          decodeURIComponent(params.runId),
          decodeURIComponent(params.step),
        ),
      );
    }
  }, [orgSlug, params.runId, params.step, router, tenantSlug]);

  return null;
}
