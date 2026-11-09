'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { WorkflowPicture } from '@/components/dashboard/workflows/builder/workflow-picture';
import { JsonView } from '@/components/dashboard/workflows/json-view';
import { RunStepList } from '@/components/dashboard/workflows/run-step-list';
import { ExposureBadge, RunStatusBadge } from '@/components/dashboard/workflows/workflow-badges';
import { useRunStream } from '@/hooks/dashboard/use-run-stream';
import { useWorkflowCaller } from '@/hooks/dashboard/use-workflow-caller';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  cancelWorkflowRun,
  getApiErrorMessage,
  getWorkflowExecution,
  getWorkflowVersion,
  rerunWorkflowRun,
  retryWorkflowRun,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Execution } from '@/types/workflows';
import type { WorkflowGraph } from '@/types/workflow-graph';
import { getTenantScopedPath, getWorkflowApprovalPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';
import { getActorWord } from '@/utils/workflow-actor';

type RunAction = 'cancel' | 'rerun' | 'retry';

function waitingApprovalKey(run: Execution, graph: WorkflowGraph | undefined) {
  for (const step of run.steps) {
    if (step.passes?.approval === 'waiting') {
      return step.key;
    }

    const node = graph?.nodes.find((candidate) => candidate.key === step.key);

    if (step.phase === 'running' && node?.kind === 'approval') {
      return step.key;
    }
  }

  return null;
}

/** One run: how it stands, every step's data, and the buttons that act on it. */
export default function WorkflowRunPage() {
  const t = useTranslations('dashboard.workflows.run');
  const tCause = useLooseTranslations('dashboard.workflows.cause');
  const tActor = useTranslations('dashboard.workflows.actor');
  const tNav = useNavLabels();
  const params = useParams<{ runId: string }>();
  const runId = decodeURIComponent(params.runId);
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const caller = useWorkflowCaller();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const [pendingAction, setPendingAction] = useState<RunAction | null>(null);
  const {
    data: run,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getWorkflowExecution(orgSlug ?? '', tenantSlug, runId),
    queryKey: ['workflow-run', orgSlug, tenantSlug, runId],
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 15_000 : false),
    retry: false,
  });
  const { data: version } = useQuery({
    enabled: Boolean(run),
    queryFn: () =>
      getWorkflowVersion(orgSlug ?? '', tenantSlug, run?.workflowId ?? '', run?.version ?? 0),
    queryKey: ['workflow-version', orgSlug, tenantSlug, run?.workflowId, run?.version],
  });

  useRunStream(orgSlug, tenantSlug, runId, run?.status === 'running');

  const { isPending, mutate } = useMutation({
    mutationFn: (action: RunAction) => {
      const execute = {
        cancel: cancelWorkflowRun,
        rerun: rerunWorkflowRun,
        retry: retryWorkflowRun,
      }[action];

      return execute(orgSlug ?? '', tenantSlug, runId);
    },
    onError: (mutationError) => {
      setPendingAction(null);
      showNotification({
        message: getApiErrorMessage(mutationError, t('actionFailed')),
        type: 'error',
      });
    },
    onSuccess: async (decided, action) => {
      setPendingAction(null);
      showNotification({ message: t(`toasts.${action}`), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['workflow-run', orgSlug, tenantSlug, runId],
      });
      await queryClient.invalidateQueries({ queryKey: ['workflow-runs', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);

      if (action !== 'cancel') {
        router.push(runPath(decided.executionId));
      }
    },
  });

  function runPath(id: string) {
    return getTenantScopedPath(
      isTenantView,
      orgSlug,
      tenantSlug,
      `workflows/runs/${id}`,
      `workflows/runs/${id}`,
    );
  }

  const workflowsPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'workflows',
    'workflows',
  );
  const runsPath = `${workflowsPath}?tab=runs`;
  const isOwnRun = run ? run.actingFor === caller : false;
  const canCancel = run?.status === 'running' && (isOwnRun || hasPermission('Workflows', 'Manage'));
  const canRestart =
    (run?.status === 'failed' || run?.status === 'timed_out') &&
    isOwnRun &&
    hasPermission('Workflows', 'Run') &&
    run.mode !== 'test';
  const approvalKey = run ? waitingApprovalKey(run, version?.graph) : null;
  const canDecide = hasPermission('Workflows', 'Approve');
  const headerTrail = isTenantView
    ? [{ href: runsPath, icon: 'account_tree' }, { title: t('title') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview'),
          title: companyDisplayName,
        },
        { href: runsPath, title: tNav.label('Workflows') },
        { title: t('title') },
      ];
  const modalText = pendingAction
    ? {
        confirmationValue: undefined,
        description: t(`confirm.${pendingAction}Description`),
        primaryActionLabel: t(`confirm.${pendingAction}Action`),
        secondaryActionLabel: t('confirm.dismiss'),
        title: t(`confirm.${pendingAction}Title`),
      }
    : null;

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Workflows"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <div className="mx-auto flex w-full max-w-240 flex-col gap-4">
            {error ? (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
                {getApiErrorMessage(error, t('loadFailed'))}
              </p>
            ) : null}

            {isLoading ? <p className="text-sm text-textGray">{t('loading')}</p> : null}

            {run ? (
              <>
                {version ? (
                  <div className="relative flex h-96 flex-col overflow-hidden rounded-lg border border-borderGray bg-cardBg">
                    <WorkflowPicture run={run} workflow={version} />
                  </div>
                ) : null}

                {approvalKey ? (
                  <div className="flex flex-col gap-2 rounded-lg bg-orange/10 px-4 py-3 text-sm text-orange sm:flex-row sm:items-center sm:justify-between">
                    <span className="flex items-center gap-2 font-medium">
                      <span className="material-symbols-rounded text-base!" aria-hidden>
                        hourglass_top
                      </span>
                      {t('needsDecision')}
                    </span>
                    {canDecide && orgSlug ? (
                      <Link
                        className="font-semibold text-primary hover:underline"
                        href={getWorkflowApprovalPath(orgSlug, tenantSlug, runId, approvalKey)}
                      >
                        {t('openDecision')}
                      </Link>
                    ) : null}
                  </div>
                ) : null}

                {run.pass ? (
                  <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs text-textGray">
                    {t.rich('passOf', {
                      index: run.pass.index + 1,
                      loop: () => (
                        <Link
                          className="font-semibold text-primary hover:underline"
                          href={runPath(run.pass?.executionId ?? '')}
                        >
                          {run.pass?.step}
                        </Link>
                      ),
                    })}
                  </p>
                ) : null}

                <section className="rounded-lg border border-borderGray bg-cardBg p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-base font-bold text-white">
                        {t('heading', { name: version?.name ?? t('fallbackName') })}
                      </h1>
                      <RunStatusBadge status={run.status} />
                      <ExposureBadge exposure={run.exposure} />
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {canCancel ? (
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => setPendingAction('cancel')}
                        >
                          {t('cancel')}
                        </Button>
                      ) : null}
                      {canRestart ? (
                        <>
                          <Button
                            className="w-auto"
                            type="button"
                            variant="outline"
                            onClick={() => setPendingAction('retry')}
                          >
                            {t('retry')}
                          </Button>
                          <Button
                            className="w-auto"
                            type="button"
                            variant="outline"
                            onClick={() => setPendingAction('rerun')}
                          >
                            {t('rerun')}
                          </Button>
                        </>
                      ) : null}
                    </div>
                  </div>
                  <dl className="mt-4 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                    <div>
                      <dt className="text-textGray">{t('cause')}</dt>
                      <dd className="text-white">
                        {tCause.has(run.cause) ? tCause(run.cause) : run.cause}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-textGray">{t('actingFor')}</dt>
                      <dd className="text-white">{tActor(getActorWord(run.actingFor, caller))}</dd>
                    </div>
                    <div>
                      <dt className="text-textGray">{t('started')}</dt>
                      <dd className="text-white">{formatBackendDateTime(run.createdAt)}</dd>
                    </div>
                    <div>
                      <dt className="text-textGray">{t('deadline')}</dt>
                      <dd className="text-white">{formatBackendDateTime(run.deadline)}</dd>
                    </div>
                  </dl>
                </section>

                <section>
                  <h2 className="mb-2 text-xs font-semibold text-textGray">{t('startData')}</h2>
                  <JsonView value={run.input} withheld={run.inputWithheld} />
                </section>

                <section>
                  <h2 className="mb-2 text-xs font-semibold text-textGray">{t('steps')}</h2>
                  <RunStepList steps={run.steps} />
                </section>
              </>
            ) : null}
          </div>
        </main>
      </div>

      <ActionConfirmModal
        confirmationValue=""
        content={modalText}
        isSubmitting={isPending}
        onClose={() => setPendingAction(null)}
        onConfirm={() => pendingAction && mutate(pendingAction)}
        onConfirmationChange={() => {}}
      />
    </div>
  );
}
