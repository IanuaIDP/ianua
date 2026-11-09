'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { RunTraceModal } from '@/components/dashboard/tenant-detail/sections/agents/runs/run-trace-modal';
import { RunsTable } from '@/components/dashboard/tenant-detail/sections/agents/runs/runs-table';
import { RunsPagination } from '@/components/dashboard/tenant-detail/sections/agents/runs/runs-pagination';
import { StartRunModal } from '@/components/dashboard/tenant-detail/sections/agents/runs/start-run-modal';
import { useNotification } from '@/components/ui/notifications';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import {
  cancelAgentRun,
  deriveErrorMessage,
  getAgentDelegations,
  getAgentRuns,
  getApiErrorMessage,
  getTenantModelProviders,
  startAgentRun,
} from '@/lib/api';
import type { StartAgentRunPayload } from '@/lib/api/services/runs';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { RunSummary } from '@/types/run';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';

export function RunsSection() {
  const { orgSlug, tenantSlug, agentId } = useAgentRouteParams();
  return <AgentRuns key={`${orgSlug}/${tenantSlug}/${agentId}`} />;
}

function AgentRuns() {
  const t = useTranslations('dashboard.agents.runs');
  const tErrors = useTranslations('common.errors');
  const { agentId, isTenantView, orgSlug, tenantSlug } = useAgentRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canStartRun = hasPermission('Agents', 'Delegate');
  const canStopRun = hasPermission('Agents', 'Delegate');
  const canViewRuns = hasPermission('Agents', 'View');
  const canReviewApproval = hasPermission('Agents', 'Approve');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();

  const [isStartModalOpen, setIsStartModalOpen] = useState(false);
  const [traceRun, setTraceRun] = useState<RunSummary | null>(null);
  const [cursors, setCursors] = useState<string[]>([]);
  const [limit, setLimit] = useState(20);
  const after = cursors.at(-1);

  const runsQueryKey = ['agent-runs', orgSlug, tenantSlug, agentId];
  const agentDetailPath = isTenantView
    ? orgSlug
      ? getAgentPath(orgSlug, tenantSlug, agentId)
      : undefined
    : getAgentManagementPath(tenantSlug, agentId);
  const approvalsHref = agentDetailPath ? `${agentDetailPath}/approvals` : '#';

  const {
    data: runs,
    error,
    isLoading,
    isFetching,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId && canViewRuns),
    queryFn: () => getAgentRuns(orgSlug ?? '', tenantSlug, agentId, { after, limit }),
    queryKey: [...runsQueryKey, limit, after],
  });

  const { data: providers } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
  });

  const { data: delegations } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentDelegations(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-delegations', orgSlug, tenantSlug, agentId],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateRuns() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: runsQueryKey }),
      queryClient.invalidateQueries({ queryKey: ['agent-run', orgSlug, tenantSlug, agentId] }),
    ]);

    if (orgSlug) {
      await invalidateAuditLogQueries(queryClient, orgSlug);
    }
  }

  const { isPending: isStartingRun, mutate: submitStartRun } = useMutation({
    mutationFn: (payload: StartAgentRunPayload) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return startAgentRun(orgSlug, tenantSlug, agentId, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('startFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsStartModalOpen(false);
      setCursors([]);
      showNotification({ message: t('started'), type: 'success' });
      await invalidateRuns();
    },
  });

  async function handleStopRun(run: RunSummary) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await cancelAgentRun(orgSlug, tenantSlug, agentId, run.id);
    await invalidateRuns();
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('start')}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={canStartRun ? () => setIsStartModalOpen(true) : undefined}
      >
        <RunsTable
          approvalsHref={approvalsHref}
          canReviewApproval={canReviewApproval}
          canStop={canStopRun}
          canView={canViewRuns}
          isLoading={isLoading}
          providers={providers ?? []}
          runs={canViewRuns ? (runs?.items ?? []) : []}
          onStopRun={handleStopRun}
          onViewTrace={setTraceRun}
        />
        {canViewRuns ? (
          <RunsPagination
            page={cursors.length + 1}
            limit={limit}
            hasNext={Boolean(runs?.nextCursor) && !error}
            isLoading={isFetching}
            onPrevious={() => setCursors((previous) => previous.slice(0, -1))}
            onNext={() => {
              const next = runs?.nextCursor;
              if (next) setCursors((previous) => [...previous, next]);
            }}
            onLimitChange={(size) => {
              setLimit(size);
              setCursors([]);
            }}
          />
        ) : null}
      </DashboardDataCard>

      <StartRunModal
        delegations={delegations ?? []}
        isSubmitting={isStartingRun}
        open={isStartModalOpen}
        providers={providers ?? []}
        onClose={() => setIsStartModalOpen(false)}
        onSubmit={submitStartRun}
      />

      <RunTraceModal run={canViewRuns ? traceRun : null} onClose={() => setTraceRun(null)} />
    </>
  );
}
