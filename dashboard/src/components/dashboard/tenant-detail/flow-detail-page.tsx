'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { FlowActionsMenu } from '@/components/dashboard/tenant-detail/sections/flows/flow-actions-menu';
import { FlowStageTimeline } from '@/components/dashboard/tenant-detail/sections/flows/flow-stage-timeline';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { useNotification } from '@/components/ui/notifications';
import { useFlowText } from '@/hooks/dashboard/use-flow-text';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useFlowRouteParams } from '@/hooks/tenants/use-flow-route-params';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  deriveErrorMessage,
  executeTenantFlowAction,
  getApiErrorMessage,
  getTenantAgents,
  getTenantFlow,
  getTenantModelProviders,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Flow, FlowAction } from '@/types/flow';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';
import { getFlowAgentCount, getFlowNodeCounts, getFlowStageDisplay } from '@/utils/flow';

export default function FlowDetailPage() {
  const t = useTranslations('dashboard.flows.detail');
  const tFlows = useTranslations('dashboard.flows');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const { actionModalContent } = useFlowText();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { flowId, isTenantView, orgSlug, tenantSlug } = useFlowRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCancelFlow = hasPermission('Workflows', 'Run');
  const canDeleteFlow = hasPermission('Workflows', 'Run') || hasPermission('Workflows', 'Delete');

  const [isCancelOpen, setIsCancelOpen] = useState(false);

  const flowsPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'flows', 'flows');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const {
    data: flow,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && flowId),
    queryFn: () => getTenantFlow(orgSlug ?? '', tenantSlug, flowId),
    queryKey: ['tenant-flow', orgSlug, tenantSlug, flowId],
  });

  const { data: agents } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-agents', orgSlug, tenantSlug],
  });

  const { data: providers } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
  });

  const agentNameById = new Map((agents ?? []).map((agent) => [agent.id, agent.name]));
  const providerModelById = new Map(
    (providers ?? []).map((provider) => [provider.id, provider.model]),
  );

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateFlow() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-flow', orgSlug, tenantSlug, flowId] });
    await queryClient.invalidateQueries({ queryKey: ['tenant-flows', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function handleFlowAction(target: Flow, action: FlowAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantFlowAction(orgSlug, tenantSlug, target, action);

    if (action === 'Delete') {
      router.push(flowsPath);
      return;
    }

    await invalidateFlow();
  }

  const { isPending: isCancelling, mutate: submitCancelFlow } = useMutation({
    mutationFn: () => {
      if (!orgSlug || !flow) {
        throw new Error(tErrors('organizationMissing'));
      }

      return executeTenantFlowAction(orgSlug, tenantSlug, flow, 'Cancel');
    },
    onSuccess: async () => {
      setIsCancelOpen(false);
      showNotification({ message: tFlows('toasts.cancelled'), type: 'success' });
      await invalidateFlow();
    },
    onError: (mutationError) => {
      setIsCancelOpen(false);
      showNotification({
        message: getApiErrorMessage(mutationError, t('cancelFailed')),
        type: 'error',
      });
    },
  });

  const headerTrail = isTenantView
    ? [{ href: flowsPath, icon: 'account_tree' }, { title: flow?.name ?? t('fallbackName') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: flowsPath, title: navLabels.label('Flows') },
        { title: flow?.name ?? t('fallbackName') },
      ];

  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);

  const stageDisplay = flow ? getFlowStageDisplay(flow) : { current: 0, total: 0 };
  const nodeCounts = flow ? getFlowNodeCounts(flow) : { settled: 0, total: 0 };
  const agentCount = flow ? getFlowAgentCount(flow) : 0;

  const flowContent = (
    <>
      {errorMessage ? (
        <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {errorMessage}
        </p>
      ) : null}

      {isLoading ? (
        <p className="text-sm text-textGray">{t('loading')}</p>
      ) : flow ? (
        <div className="mx-auto flex w-full max-w-360 flex-col gap-4">
          <div className="grid gap-4 lg:grid-cols-[2fr_3fr]">
            <div className="flex flex-col overflow-hidden rounded-lg border border-borderGray bg-cardBg">
              <div className="flex items-start justify-between gap-3 p-4">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-focus/15 text-focus">
                    <span className="material-symbols-rounded" aria-hidden>
                      account_tree
                    </span>
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="truncate text-base font-bold text-white">{flow.name}</h1>
                      <DashboardStatusBadge status={flow.status} />
                    </div>
                    {flow.description ? (
                      <p className="mt-1 text-xs text-textGray">{flow.description}</p>
                    ) : null}
                  </div>
                </div>
                <FlowActionsMenu
                  canCancel={canCancelFlow}
                  canDelete={canDeleteFlow}
                  flow={flow}
                  onActionConfirm={handleFlowAction}
                />
              </div>

              <div className="grid flex-1 grid-cols-1 border-t border-borderGray sm:grid-cols-2">
                <div className="flex items-center gap-1 border-b border-borderGray px-4 py-3 text-[12 text-textGray sm:border-b-0 sm:border-r">
                  {t('id')} <span className="text-white">{flow.id.slice(0, 8)}</span>
                </div>
                <div className="flex items-center gap-1 px-4 py-3 text-xs text-textGray">
                  {t('created')}{' '}
                  <span className="text-white">{formatBackendDateTime(flow.createdAt)}</span>
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-borderGray bg-cardBg p-4">
              <h2 className="text-sm font-bold text-white">{t('summary')}</h2>
              <dl className="mt-3 grid grid-cols-1 overflow-hidden rounded-[10px] border border-borderGray text-sm sm:grid-cols-3">
                <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                  <dt className="text-textGray">{t('stages')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {stageDisplay.current}/{stageDisplay.total}
                  </dd>
                </div>
                <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                  <dt className="text-textGray">{t('nodesSettled')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {nodeCounts.settled}/{nodeCounts.total}
                  </dd>
                </div>
                <div className="flex flex-col justify-center px-4 py-3">
                  <dt className="text-textGray">{t('agentsInvolved')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">{agentCount}</dd>
                </div>
              </dl>
            </div>
          </div>

          <DashboardDataCard
            description=""
            title={t('stages')}
            secondaryActionLabel={
              canCancelFlow && flow.status === 'Running' ? t('cancel') : undefined
            }
            onSecondaryActionClick={
              canCancelFlow && flow.status === 'Running' ? () => setIsCancelOpen(true) : undefined
            }
          >
            <div className="px-4 pb-4">
              <FlowStageTimeline
                agentNameById={agentNameById}
                flow={flow}
                isTenantView={isTenantView}
                orgSlug={orgSlug}
                providerModelById={providerModelById}
                tenantSlug={tenantSlug}
              />
            </div>
          </DashboardDataCard>
        </div>
      ) : null}
    </>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Flows"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">{flowContent}</main>
      </div>

      <ActionConfirmModal
        confirmationValue=""
        content={isCancelOpen && flow ? actionModalContent(flow).Cancel : null}
        isSubmitting={isCancelling}
        onClose={() => setIsCancelOpen(false)}
        onConfirm={() => submitCancelFlow()}
        onConfirmationChange={() => {}}
      />
    </div>
  );
}
