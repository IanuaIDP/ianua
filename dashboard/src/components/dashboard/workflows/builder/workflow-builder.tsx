'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import {
  AddStepDrawer,
  makeStepFromItem,
  type DrawerItem,
} from '@/components/dashboard/workflows/builder/add-step-drawer';
import { ToolButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import {
  BuilderContextProvider,
  type BuilderContextValue,
} from '@/components/dashboard/workflows/builder/builder-context';
import { BuildForMeModal } from '@/components/dashboard/workflows/builder/build-for-me-modal';
import { RunBar } from '@/components/dashboard/workflows/builder/run-bar';
import { TryItModal } from '@/components/dashboard/workflows/builder/try-it-modal';
import { BuilderTopBar } from '@/components/dashboard/workflows/builder/builder-top-bar';
import {
  CARD_HEIGHT,
  CARD_WIDTH,
  MAX_STEPS,
  TRIGGER_KEY,
} from '@/components/dashboard/workflows/builder/constants';
import { hasUnsavedChanges } from '@/components/dashboard/workflows/builder/draft-saving';
import {
  clearDraftStash,
  readDraftStash,
} from '@/components/dashboard/workflows/builder/draft-stash';
import { HeldBanner } from '@/components/dashboard/workflows/builder/held-banner';
import { isSameJson } from '@/components/dashboard/workflows/builder/graph';
import { PublishSheet } from '@/components/dashboard/workflows/builder/publish-sheet';
import { SettingsPanel } from '@/components/dashboard/workflows/builder/settings-panel';
import {
  getPublishHints,
  makeOperationLookup,
} from '@/components/dashboard/workflows/builder/step-issues';
import { StepMark } from '@/components/dashboard/workflows/builder/step-mark';
import { StepPanel } from '@/components/dashboard/workflows/builder/step-panel';
import { StepsOutline } from '@/components/dashboard/workflows/builder/steps-outline';
import { TriggerPanel } from '@/components/dashboard/workflows/builder/steps/trigger-panel';
import { TouchesPanel } from '@/components/dashboard/workflows/builder/touches-panel';
import { useDraftSaving } from '@/components/dashboard/workflows/builder/use-draft-saving';
import { useDraftStream } from '@/components/dashboard/workflows/builder/use-draft-stream';
import { useStepText } from '@/components/dashboard/workflows/builder/use-step-text';
import { useWorkflowRouteParams } from '@/components/dashboard/workflows/builder/use-workflow-route-params';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { VersionsPanel } from '@/components/dashboard/workflows/builder/versions-panel';
import {
  getFlowLevels,
  getLeakingSteps,
} from '@/components/dashboard/workflows/builder/what-it-touches';
import { WirePanel } from '@/components/dashboard/workflows/builder/wire-panel';
import {
  WorkflowCanvas,
  type CanvasEditing,
} from '@/components/dashboard/workflows/builder/workflow-canvas';
import {
  toWorkingCopy,
  type Point,
  type StepPlacement,
  type WorkingCopy,
} from '@/components/dashboard/workflows/builder/working-copy';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useRunStream } from '@/hooks/dashboard/use-run-stream';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  getApiErrorMessage,
  getBuilderAccounts,
  getBuilderWorkflow,
  getWorkflowExecution,
  getWorkflowIntegrations,
  getWorkflowOperations,
  isConflictError,
  startNextWorkflowDraft,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { WorkflowNode } from '@/types/workflow-graph';
import type { Workflow } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

/** The builder: a workflow as a picture, and, on a draft, the place to change it. */
export default function WorkflowBuilder() {
  const t = useTranslations('dashboard.workflowBuilder');
  const { isTenantView, orgSlug, tenantSlug, workflowId } = useWorkflowRouteParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const navLabels = useNavLabels();
  const { showNotification } = useNotification();
  const { hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const canUpdate = hasPermission('Workflows', 'Update');
  const canCreate = hasPermission('Workflows', 'Create');
  const canDelete = hasPermission('Workflows', 'Delete');
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const { companyDisplayName } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const versionParam = Number(searchParams.get('version'));
  const openVersion = Number.isInteger(versionParam) && versionParam > 0 ? versionParam : null;
  const runId = searchParams.get('run');
  const [testRunId, setTestRunId] = useState<string | null>(null);
  const [isTryingIt, setIsTryingIt] = useState(false);
  const [isBuilding, setIsBuilding] = useState(false);
  const activeRunId = runId ?? testRunId;
  const isOlderVersion = openVersion !== null;
  const isRunView = Boolean(runId);
  const viewCentreRef = useRef<(() => Point) | null>(null);
  const [isOutlineOpen, setIsOutlineOpen] = useState(false);
  const [isPublishOpen, setIsPublishOpen] = useState(false);

  const copy = useWorkingCopy((state) => state.copy);
  const outsideChange = useWorkingCopy((state) => state.outsideChange);
  const selection = useWorkingCopy((state) => state.selection);
  const panel = useWorkingCopy((state) => state.panel);
  const past = useWorkingCopy((state) => state.past);
  const future = useWorkingCopy((state) => state.future);
  const isDrawerOpen = useWorkingCopy((state) => state.isDrawerOpen);
  const saved = useWorkingCopy((state) => state.saved);
  const loadedVersion = useWorkingCopy((state) => state.version);
  const loadedWorkflowId = useWorkingCopy((state) => state.workflowId);
  const status = useWorkingCopy((state) => state.status);

  const scopedPath = useCallback(
    (segment: string) => getTenantScopedPath(isTenantView, orgSlug, tenantSlug, segment, segment),
    [isTenantView, orgSlug, tenantSlug],
  );

  const { data: run } = useQuery({
    enabled: Boolean(orgSlug && activeRunId),
    queryFn: () => getWorkflowExecution(orgSlug ?? '', tenantSlug, activeRunId ?? ''),
    queryKey: ['workflow-run', orgSlug, tenantSlug, activeRunId],
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 15_000 : false),
  });
  const shownVersion = openVersion ?? (runId ? run?.version : undefined);

  const {
    data: workflow,
    error: workflowError,
    isLoading: isLoadingWorkflow,
    refetch: refetchWorkflow,
  } = useQuery({
    enabled: Boolean(orgSlug && workflowId) && (!runId || Boolean(run)),
    gcTime: 0,
    queryFn: () => getBuilderWorkflow(orgSlug ?? '', tenantSlug, workflowId ?? '', shownVersion),
    queryKey: ['workflow-builder', orgSlug, tenantSlug, workflowId, shownVersion ?? 'latest'],
    refetchOnWindowFocus: false,
    staleTime: Number.POSITIVE_INFINITY,
  });

  const { data: latestWorkflow } = useQuery({
    enabled: Boolean(orgSlug && workflowId) && shownVersion !== undefined,
    queryFn: () => getBuilderWorkflow(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    queryKey: ['workflow-builder-latest', orgSlug, tenantSlug, workflowId],
  });

  const { data: operations, isSuccess: operationsReady } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getWorkflowOperations(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-operations', orgSlug, tenantSlug],
  });

  const { data: integrations } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getWorkflowIntegrations(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-integrations', orgSlug, tenantSlug],
  });

  const { data: accounts, isSuccess: accountsReady } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getBuilderAccounts(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-builder-accounts', orgSlug, tenantSlug],
  });

  useRunStream(orgSlug, tenantSlug, activeRunId ?? '', run?.status === 'running');

  const runSteps = useMemo(
    () => (run ? new Map(run.steps.map((state) => [state.key, state])) : undefined),
    [run],
  );

  const text = useStepText(integrations);
  const lookup = useMemo(() => makeOperationLookup(operations), [operations]);

  const load = useCallback((next: Workflow, restored?: WorkingCopy) => {
    useWorkingCopy.getState().load(next, { restored });
  }, []);

  const handleWorkflowLoaded = useCallback(
    (next: Workflow) => {
      if (!orgSlug) {
        return;
      }

      if (isOlderVersion || isRunView) {
        load(next);

        return;
      }

      const stash = readDraftStash(orgSlug, tenantSlug, next.id);

      if (!stash || isSameJson(stash.copy, toWorkingCopy(next)) || next.status !== 'draft') {
        clearDraftStash(orgSlug, tenantSlug, next.id);
        load(next);

        return;
      }

      if (stash.baseRevision === next.revision) {
        load(next, stash.copy);

        return;
      }

      load(next);
      useWorkingCopy.getState().setOutsideChange({ kind: 'stash', stash });
    },
    [isOlderVersion, isRunView, load, orgSlug, tenantSlug],
  );

  useEffect(() => {
    if (workflow) {
      handleWorkflowLoaded(workflow);
    }
  }, [handleWorkflowLoaded, workflow]);

  const newWorkflowName = t('newWorkflowName');

  useEffect(() => {
    if (workflowId || !orgSlug) {
      return;
    }

    const stash = readDraftStash(orgSlug, tenantSlug, null);

    useWorkingCopy.getState().startNew(newWorkflowName, stash?.copy);
  }, [newWorkflowName, orgSlug, tenantSlug, workflowId]);

  const canEdit =
    !isRunView &&
    !isOlderVersion &&
    (workflowId ? status === 'draft' : true) &&
    !isLoadingPermissions &&
    (workflowId ? canUpdate : canCreate);

  useEffect(() => {
    useWorkingCopy.getState().setEditable(canEdit);
  }, [canEdit]);

  const onCreated = useCallback(
    (created: Workflow) => {
      void queryClient.invalidateQueries({ queryKey: ['workflows', orgSlug, tenantSlug] });
      void invalidateAuditLogQueries(queryClient, orgSlug);
      router.replace(scopedPath(`workflows/${created.id}`));
    },
    [orgSlug, queryClient, router, scopedPath, tenantSlug],
  );

  const { flush, save } = useDraftSaving({
    isCatalogReady: operationsReady,
    lookup,
    onCreated,
    orgSlug,
    tenantSlug,
  });

  const checkForOutsideChange = useCallback(async () => {
    const state = useWorkingCopy.getState();

    if (!orgSlug || !state.workflowId || state.saveStatus === 'saving') {
      return;
    }

    const latest = await getBuilderWorkflow(orgSlug, tenantSlug, state.workflowId);
    const current = useWorkingCopy.getState();

    if (latest.revision === current.revision || current.saveStatus === 'saving') {
      return;
    }

    const isClean = !hasUnsavedChanges(current.copy, current.saved, lookup);

    if (isClean) {
      load(latest);
      showNotification({ message: t('changedByColleague'), type: 'default' });

      return;
    }

    useWorkingCopy.getState().setOutsideChange({ kind: 'latest', latest });
  }, [load, lookup, orgSlug, showNotification, t, tenantSlug]);

  useDraftStream({
    enabled: canEdit,
    onChanged: () => void checkForOutsideChange(),
    orgSlug,
    tenantSlug,
    workflowId,
  });

  const { isPending: isStartingDraft, mutate: startDraft } = useMutation({
    mutationFn: () => startNextWorkflowDraft(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    onError: async (error) => {
      if (isConflictError(error)) {
        await refetchWorkflow();

        return;
      }

      showNotification({
        message: getApiErrorMessage(error, t('startDraftFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('draftStarted'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['workflows', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      await refetchWorkflow();
    },
  });

  useEffect(() => {
    function handleKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;

      if (event.key === 'Escape') {
        useWorkingCopy.getState().closeDrawer();
      }

      if (target?.closest('input, textarea, [contenteditable="true"]')) {
        return;
      }

      const store = useWorkingCopy.getState();

      if (!store.editable) {
        return;
      }

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'z') {
        event.preventDefault();
        store.applyHistory(event.shiftKey ? 'redo' : 'undo');

        return;
      }

      if (
        (event.key === 'Delete' || event.key === 'Backspace') &&
        store.selection?.type === 'step'
      ) {
        store.removeSelected(store.selection.key);
      }
    }

    function closeDrawerOnOutsidePress(event: PointerEvent) {
      if (!(event.target as Element).closest('[data-builder-bar], [data-add-button]')) {
        useWorkingCopy.getState().closeDrawer();
      }
    }

    document.addEventListener('keydown', handleKey);
    document.addEventListener('pointerdown', closeDrawerOnOutsidePress);

    return () => {
      document.removeEventListener('keydown', handleKey);
      document.removeEventListener('pointerdown', closeDrawerOnOutsidePress);
    };
  }, []);

  const flags = useMemo(() => {
    const leaking = new Set(getLeakingSteps(copy).map((step) => step.key));
    const problems = new Set(
      copy.nodes
        .filter((node) => operationsReady && getPublishHints(copy, node, lookup).length > 0)
        .map((node) => node.key),
    );

    return { leaking, problems };
  }, [copy, lookup, operationsReady]);

  const levels = useMemo(() => getFlowLevels(copy), [copy]);

  const contextValue: BuilderContextValue = useMemo(
    () => ({
      accounts: accounts ?? [],
      accountsReady,
      flush,
      integrations: integrations ?? [],
      isRunView,
      isTestRun: run?.mode === 'test',
      lookup,
      operations: operations ?? [],
      operationsReady,
      orgSlug,
      runSteps,
      save,
      tenantPathFor: scopedPath,
      tenantSlug,
      text,
    }),
    [
      accounts,
      accountsReady,
      flush,
      integrations,
      isRunView,
      lookup,
      operations,
      run?.mode,
      operationsReady,
      orgSlug,
      runSteps,
      save,
      scopedPath,
      tenantSlug,
      text,
    ],
  );

  function placeNewStep(item: DrawerItem, placement: StepPlacement) {
    const made = makeStepFromItem(
      item,
      { nameOf: (kind) => text.getKindLabel(kind) },
      operations ?? [],
    );

    if (!made || copy.nodes.length >= MAX_STEPS) {
      if (copy.nodes.length >= MAX_STEPS) {
        showNotification({ message: t('tooManySteps'), type: 'error' });
      }

      return;
    }

    useWorkingCopy.getState().addStepAt(made, placement);
  }

  function addFromDrawer(item: DrawerItem) {
    const { addingAt } = useWorkingCopy.getState();

    placeNewStep(item, addingAt ?? { at: viewCentreRef.current?.() ?? { x: 360, y: 60 } });
  }

  const editing: CanvasEditing | undefined = canEdit
    ? {
        onAddStep: (placement) => useWorkingCopy.getState().openDrawer(placement),
        onConnect: (edge) => {
          const result = useWorkingCopy.getState().connect(edge);

          if (result === 'circle') {
            showNotification({ message: t('wouldLoop'), type: 'error' });
          }

          if (result === 'full') {
            showNotification({ message: t('tooManyArrows'), type: 'error' });
          }
        },
        onDropStep: (data, point) => {
          placeNewStep(JSON.parse(data) as DrawerItem, {
            at: { x: point.x - CARD_WIDTH / 2, y: point.y - CARD_HEIGHT / 2 },
          });
        },
        onMove: (key, point) => useWorkingCopy.getState().moveTo(key, point),
        onMoveEnd: () => {},
        onMoveStart: () => useWorkingCopy.getState().remember(),
      }
    : undefined;

  function describeStep(node: WorkflowNode | null) {
    if (!node) {
      return {
        line: text.getTriggerLine(copy.trigger),
        mark: <StepMark trigger={copy.trigger} />,
        title: text.getTriggerTitle(copy.trigger),
      };
    }

    const integration =
      node.kind === 'action'
        ? (integrations?.find((item) => item.key === node.integration) ?? null)
        : null;

    return {
      line: text.getStepLine(node),
      mark: <StepMark integration={integration} node={node} />,
      title: node.name || text.getKindLabel(node.kind),
    };
  }

  const heldNeed = workflow?.needsAccount ?? null;
  const canStartDraft =
    Boolean(workflowId) && !isOlderVersion && !isRunView && canCreate && status === 'published';
  const canPublish = canEdit && Boolean(workflowId);
  const canTry = canPublish && hasPermission('Workflows', 'Run');
  const pageName = workflow?.name ?? copy.name;
  const headerTrail = isTenantView
    ? [{ href: scopedPath('workflows'), icon: 'account_tree' }, { title: pageName }]
    : [
        { href: scopedPath('overview'), title: companyDisplayName },
        { href: scopedPath('workflows'), title: navLabels.label('Workflows') },
        { title: pageName },
      ];

  const errorMessage = workflowError ? getApiErrorMessage(workflowError, t('loadFailed')) : null;
  const isLoading = workflowId
    ? isLoadingWorkflow || !saved || loadedWorkflowId !== workflowId
    : loadedWorkflowId !== null;

  function renderSidePanel() {
    if (selection?.type === 'step') {
      return <StepPanel key={selection.key} stepKey={selection.key} />;
    }

    if (selection?.type === 'trigger') {
      return <TriggerPanelFrame />;
    }

    if (selection?.type === 'wire') {
      return <WirePanel edge={selection.edge} isImplied={selection.isImplied} />;
    }

    if (panel === 'settings') {
      return <SettingsPanel />;
    }

    if (panel === 'versions' && workflowId) {
      return (
        <VersionsPanel
          canDelete={canDelete}
          latestVersion={latestWorkflow?.version ?? loadedVersion}
          onChanged={() => void refetchWorkflow()}
          openVersion={openVersion}
          workflowId={workflowId}
        />
      );
    }

    return <TouchesPanel />;
  }

  return (
    <BuilderContextProvider value={contextValue}>
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

          <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden p-4">
            <p className="text-sm text-textGray xl:hidden">{t('desktopOnly')}</p>

            {errorMessage ? (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
                {errorMessage}
              </p>
            ) : null}

            {isLoading ? <p className="text-sm text-textGray">{t('loading')}</p> : null}

            {!isLoading && !errorMessage ? (
              <div className="hidden min-h-0 flex-1 flex-col gap-3 xl:flex">
                <BuilderTopBar
                  canPublish={canPublish}
                  canStartDraft={canStartDraft}
                  isOlderVersion={isOlderVersion}
                  isOutlineOpen={isOutlineOpen}
                  isStartingDraft={isStartingDraft}
                  onOpenPublish={() => setIsPublishOpen(true)}
                  onStartDraft={() => startDraft()}
                  onToggleOutline={() => setIsOutlineOpen((current) => !current)}
                  onTryIt={canTry ? () => setIsTryingIt(true) : undefined}
                  workflowId={workflowId}
                />

                {run ? (
                  <RunBar onClose={testRunId ? () => setTestRunId(null) : undefined} run={run} />
                ) : null}

                {heldNeed && !isOlderVersion ? (
                  <HeldBanner
                    canStartDraft={canStartDraft}
                    isStartingDraft={isStartingDraft}
                    needsAccount={heldNeed}
                    onStartDraft={() => startDraft()}
                  />
                ) : null}

                {canEdit ? (
                  <div
                    data-builder-bar
                    className="relative z-20 flex items-center gap-2 rounded-lg bg-cardBg px-2.5 py-2"
                  >
                    <button
                      type="button"
                      aria-expanded={isDrawerOpen}
                      onClick={() =>
                        isDrawerOpen
                          ? useWorkingCopy.getState().closeDrawer()
                          : useWorkingCopy.getState().openDrawer(null)
                      }
                      className="inline-flex items-center gap-2 rounded-lg bg-surfaceRaised px-3 py-1.5 text-xs font-semibold text-white"
                    >
                      <span
                        className="material-symbols-rounded text-lg! text-primary"
                        aria-hidden="true"
                      >
                        add_circle
                      </span>
                      {t('addStep')}
                    </button>
                    {copy.nodes.length === 0 ? (
                      <ToolButton
                        icon="wand_stars"
                        label={t('buildForMe')}
                        onClick={() => setIsBuilding(true)}
                        showLabel
                      />
                    ) : null}
                    <div className="ml-auto flex items-center gap-1">
                      <ToolButton
                        disabled={past.length === 0}
                        icon="undo"
                        label={t('undo')}
                        onClick={() => useWorkingCopy.getState().applyHistory('undo')}
                      />
                      <ToolButton
                        disabled={future.length === 0}
                        icon="redo"
                        label={t('redo')}
                        onClick={() => useWorkingCopy.getState().applyHistory('redo')}
                      />
                      <ToolButton
                        icon="auto_awesome_mosaic"
                        label={t('tidy')}
                        onClick={() => useWorkingCopy.getState().tidy()}
                        showLabel
                      />
                    </div>
                    {isDrawerOpen ? <AddStepDrawer onAdd={addFromDrawer} /> : null}
                  </div>
                ) : null}

                <div className="flex min-h-0 flex-1 gap-3">
                  {isOutlineOpen ? <StepsOutline /> : null}
                  <section className="relative flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-lg bg-cardBg">
                    {canEdit && copy.nodes.length === 0 ? (
                      <div className="pointer-events-none absolute inset-x-0 top-4 z-10 flex justify-center">
                        <button
                          type="button"
                          data-add-button
                          onClick={() =>
                            useWorkingCopy
                              .getState()
                              .openDrawer({ after: TRIGGER_KEY, port: 'next' })
                          }
                          className="pointer-events-auto inline-flex items-center gap-2 rounded-lg bg-primary/15 px-3 py-1.5 text-xs font-semibold text-primary"
                        >
                          <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                            add_circle
                          </span>
                          {t('emptyBoard')}
                        </button>
                      </div>
                    ) : null}
                    <WorkflowCanvas
                      key={`${workflowId ?? 'new'}-${loadedVersion}-${copy.nodes.length === 0}`}
                      copy={copy}
                      describeStep={describeStep}
                      editing={editing}
                      flagOf={(key) =>
                        flags.leaking.has(key) ? 'leak' : flags.problems.has(key) ? 'problem' : null
                      }
                      levelOf={(from) => levels[from] ?? 'public'}
                      onSelect={(next) => useWorkingCopy.getState().select(next)}
                      runSteps={runSteps}
                      selection={selection}
                      viewCentreRef={viewCentreRef}
                    />
                  </section>
                  <aside className="flex min-h-0 w-90 shrink-0 flex-col overflow-hidden rounded-lg bg-cardBg">
                    {renderSidePanel()}
                  </aside>
                </div>
              </div>
            ) : null}
          </main>
        </div>

        {isTryingIt ? (
          <TryItModal onClose={() => setIsTryingIt(false)} onStarted={setTestRunId} />
        ) : null}

        {isBuilding ? <BuildForMeModal onClose={() => setIsBuilding(false)} /> : null}

        {workflowId && isPublishOpen ? (
          <PublishSheet
            onClose={() => setIsPublishOpen(false)}
            onPublished={() => void refetchWorkflow()}
            onReload={async () => {
              await refetchWorkflow();
            }}
          />
        ) : null}

        <Modal
          open={outsideChange !== null}
          onClose={() => useWorkingCopy.getState().setOutsideChange(null)}
          showCloseButton={false}
          title={t('outsideChange.title')}
          description={t('outsideChange.description')}
          primaryActionLabel={t('outsideChange.keepMine')}
          onPrimaryAction={() => {
            if (outsideChange?.kind === 'stash') {
              const current = useWorkingCopy.getState();

              useWorkingCopy.getState().change(() => outsideChange.stash.copy);
              current.select(null);
            }

            if (outsideChange?.kind === 'latest') {
              useWorkingCopy.getState().setBaseFromServer(outsideChange.latest);
            }

            useWorkingCopy.getState().setOutsideChange(null);
          }}
          secondaryActionLabel={t('outsideChange.takeTheirs')}
          onSecondaryAction={() => {
            if (outsideChange?.kind === 'stash' && orgSlug) {
              clearDraftStash(orgSlug, tenantSlug, workflowId);
            }

            if (outsideChange?.kind === 'latest') {
              load(outsideChange.latest);
            }

            useWorkingCopy.getState().setOutsideChange(null);
          }}
        >
          {null}
        </Modal>
      </div>
    </BuilderContextProvider>
  );
}

function TriggerPanelFrame() {
  const t = useTranslations('dashboard.workflowBuilder.panel');
  const editable = useWorkingCopy((state) => state.editable);
  const remember = useWorkingCopy((state) => state.remember);

  return (
    <div className="flex-1 overflow-auto p-4" onFocusCapture={remember}>
      <p className="text-base font-bold text-white">{t('trigger')}</p>
      <p className="mt-2 text-xs text-textGray">{t('triggerHelp')}</p>
      <TriggerPanel disabled={!editable} />
    </div>
  );
}
