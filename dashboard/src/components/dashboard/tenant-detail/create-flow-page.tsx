'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DragPreviewCard } from '@/components/dashboard/shared/drag-preview-card';
import { UnsavedChangesModal } from '@/components/dashboard/shared/unsaved-changes-modal';
import { AddFlowNodeModal } from '@/components/dashboard/tenant-detail/sections/flows/add-flow-node-modal';
import { FlowStageBlock } from '@/components/dashboard/tenant-detail/sections/flows/flow-stage-block';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { reorderById, useDragReorder } from '@/hooks/dashboard/use-drag-reorder';
import type { DragReorderPosition } from '@/hooks/dashboard/use-drag-reorder';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useUnsavedChangesGuard } from '@/hooks/dashboard/use-unsaved-changes-guard';
import {
  createTenantFlow,
  getApiErrorMessage,
  getTenantAgents,
  getTenantModelProviders,
  getTenantTools,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { FlowNodeDraft } from '@/types/flow-builder';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

type EditingNode = {
  node: FlowNodeDraft;
  stageIndex: number;
};

export default function CreateFlowPage() {
  const t = useTranslations('dashboard.flows.create');
  const tFlows = useTranslations('dashboard.flows');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [stages, setStages] = useState<FlowNodeDraft[][]>([[]]);
  const [nameError, setNameError] = useState<string | undefined>();
  const [stageErrors, setStageErrors] = useState<Record<number, string>>({});
  const [nodeModalStageIndex, setNodeModalStageIndex] = useState<number | null>(null);
  const [editingNode, setEditingNode] = useState<EditingNode | null>(null);

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
  const { data: tools } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantTools(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-tools', orgSlug, tenantSlug],
  });

  const flowsPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'flows', 'flows');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const {
    isPending: isCreating,
    isSuccess: isFlowCreated,
    mutate: submitCreateFlow,
  } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantFlow(orgSlug, tenantSlug, {
        description: description.trim() || null,
        name: name.trim(),
        stages,
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-flows', orgSlug, tenantSlug] });

      if (orgSlug) {
        await invalidateAuditLogQueries(queryClient, orgSlug);
      }

      router.push(flowsPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const hasUnsavedFlow =
    !isFlowCreated && Boolean(name.trim() || description.trim() || stages.flat().length > 0);
  const leaveGuard = useUnsavedChangesGuard(hasUnsavedFlow);

  function handleAddStage() {
    setStages((current) => [...current, []]);
  }

  function handleRemoveStage(stageIndex: number) {
    setStages((current) => current.filter((_, index) => index !== stageIndex));
    setStageErrors((current) => {
      const next: Record<number, string> = {};

      Object.entries(current).forEach(([key, value]) => {
        const index = Number(key);

        if (index < stageIndex) {
          next[index] = value;
        } else if (index > stageIndex) {
          next[index - 1] = value;
        }
      });

      return next;
    });
  }

  function handleOpenAddNode(stageIndex: number) {
    setEditingNode(null);
    setNodeModalStageIndex(stageIndex);
  }

  function handleOpenEditNode(stageIndex: number, node: FlowNodeDraft) {
    setEditingNode({ node, stageIndex });
    setNodeModalStageIndex(stageIndex);
  }

  function handleCloseNodeModal() {
    setNodeModalStageIndex(null);
    setEditingNode(null);
  }

  function handleSubmitNode(node: FlowNodeDraft) {
    if (nodeModalStageIndex === null) {
      return;
    }

    setStages((current) =>
      current.map((stageNodes, index) => {
        if (index !== nodeModalStageIndex) {
          return stageNodes;
        }

        const existingIndex = stageNodes.findIndex(
          (candidate) => candidate.clientId === node.clientId,
        );

        if (existingIndex === -1) {
          return [...stageNodes, node];
        }

        return stageNodes.map((candidate, candidateIndex) =>
          candidateIndex === existingIndex ? node : candidate,
        );
      }),
    );
    setStageErrors((current) => {
      if (!(nodeModalStageIndex in current)) {
        return current;
      }

      const next = { ...current };
      delete next[nodeModalStageIndex];
      return next;
    });
    handleCloseNodeModal();
  }

  function handleRemoveNode(stageIndex: number, clientId: string) {
    setStages((current) =>
      current.map((stageNodes, index) =>
        index === stageIndex ? stageNodes.filter((node) => node.clientId !== clientId) : stageNodes,
      ),
    );
  }

  function handleReorderNodes(
    stageIndex: number,
    fromClientId: string,
    targetClientId: string,
    position: DragReorderPosition,
  ) {
    setStages((current) =>
      current.map((stageNodes, index) => {
        if (index !== stageIndex) {
          return stageNodes;
        }

        return reorderById(
          stageNodes,
          (node) => node.clientId,
          fromClientId,
          targetClientId,
          position,
        );
      }),
    );
  }

  function handleStageDrop(fromId: string, targetId: string, position: DragReorderPosition) {
    const fromIndex = Number(fromId);
    let toIndex = Number(targetId);

    if (position === 'after') {
      toIndex += 1;
    }

    if (fromIndex === toIndex || fromIndex === toIndex - 1) {
      return;
    }

    const insertIndex = fromIndex < toIndex ? toIndex - 1 : toIndex;

    setStages((current) => {
      const next = [...current];
      const [moved] = next.splice(fromIndex, 1);
      next.splice(insertIndex, 0, moved);
      return next;
    });

    setStageErrors((current) => {
      const entryCount = Math.max(
        stages.length,
        ...Object.keys(current).map((key) => Number(key) + 1),
      );
      const errorsByIndex: (string | undefined)[] = Array.from(
        { length: entryCount },
        (_, index) => current[index],
      );
      const [movedError] = errorsByIndex.splice(fromIndex, 1);
      errorsByIndex.splice(insertIndex, 0, movedError);

      const next: Record<number, string> = {};
      errorsByIndex.forEach((value, index) => {
        if (value) {
          next[index] = value;
        }
      });

      return next;
    });
  }

  const stageItems = stages.map((stageNodes, index) => ({ id: String(index), nodes: stageNodes }));

  const {
    dragPreviewRect: stageDragPreviewRect,
    draggedItem: draggedStageItem,
    getRowProps: getStageRowProps,
    pointerY: stagePointerY,
  } = useDragReorder<{ id: string; nodes: FlowNodeDraft[] }>({
    getId: (item) => item.id,
    items: stageItems,
    onDrop: handleStageDrop,
  });

  function handleSubmit() {
    const trimmedName = name.trim();
    let hasError = false;

    if (!trimmedName) {
      setNameError(t('nameRequired'));
      hasError = true;
    } else {
      setNameError(undefined);
    }

    const nextStageErrors: Record<number, string> = {};

    stages.forEach((stageNodes, index) => {
      if (stageNodes.length === 0) {
        nextStageErrors[index] = t('stageNodeRequired');
        hasError = true;
      }
    });
    setStageErrors(nextStageErrors);

    if (hasError) {
      showNotification({
        message: t('fixFields'),
        type: 'error',
      });
      return;
    }

    submitCreateFlow();
  }

  const nodeModalNode =
    editingNode && editingNode.stageIndex === nodeModalStageIndex ? editingNode.node : null;

  const headerTrail = isTenantView
    ? [{ href: flowsPath, icon: 'account_tree' }, { title: t('crumb') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: flowsPath, title: navLabels.label('Flows') },
        { title: t('crumb') },
      ];

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Flows"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={(item) =>
            leaveGuard.leaveTo(getTenantManagementTabHref(tenantSlug, item.label))
          }
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <div className="mx-auto w-full max-w-360 overflow-hidden rounded-lg border border-borderGray bg-cardBg">
            <div className="flex flex-col gap-4 border-b border-borderGray p-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h1 className="text-base font-bold text-white">{t('title')}</h1>
                <p className="mt-1 text-xs text-textGray">{t('description')}</p>
              </div>
              <div className="flex shrink-0 items-center gap-2.5">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => leaveGuard.leaveTo(flowsPath)}
                  className="w-auto border-borderGray bg-cardBg px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
                >
                  {t('cancel')}
                </Button>
                <Button
                  type="button"
                  isLoading={isCreating}
                  onClick={handleSubmit}
                  className="w-auto bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple"
                >
                  {t('submit')}
                </Button>
              </div>
            </div>

            <div className="flex flex-col gap-4 p-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Input
                  label={t('name')}
                  placeholder={t('namePlaceholder')}
                  containerClassName="mb-0"
                  value={name}
                  onChange={(event) => {
                    setName(event.target.value);

                    if (nameError) {
                      setNameError(undefined);
                    }
                  }}
                  error={nameError}
                />
                <Input
                  label={t('descriptionLabel')}
                  placeholder={t('descriptionPlaceholder')}
                  containerClassName="mb-0"
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                />
              </div>

              {stageItems.map((stageItem) => {
                const index = Number(stageItem.id);
                const stageNodes = stageItem.nodes;

                return (
                  <div key={stageItem.id} className="flex flex-col gap-4">
                    <FlowStageBlock
                      errorMessage={stageErrors[index]}
                      nodes={stageNodes}
                      showRemoveStage={stages.length > 1}
                      stageNumber={index + 1}
                      onAddNode={() => handleOpenAddNode(index)}
                      onEditNode={(clientId) => {
                        const node = stageNodes.find(
                          (candidate) => candidate.clientId === clientId,
                        );

                        if (node) {
                          handleOpenEditNode(index, node);
                        }
                      }}
                      onRemoveNode={(clientId) => handleRemoveNode(index, clientId)}
                      onRemoveStage={() => handleRemoveStage(index)}
                      onReorderNodes={(fromClientId, targetClientId, position) =>
                        handleReorderNodes(index, fromClientId, targetClientId, position)
                      }
                      {...getStageRowProps(stageItem)}
                    />
                    {index < stages.length - 1 ? (
                      <p className="flex items-center gap-2 text-xs text-textGray">
                        <span className="material-symbols-rounded text-base" aria-hidden>
                          arrow_downward
                        </span>
                        {t('passesTo', { number: index + 2 })}
                      </p>
                    ) : null}
                  </div>
                );
              })}

              <button
                type="button"
                onClick={handleAddStage}
                className="flex h-9 items-center justify-center gap-1.5 rounded-lg border border-dashed border-borderGray text-xs font-medium text-textGray transition hover:border-primary hover:text-primary"
              >
                <span className="material-symbols-rounded text-base">add</span>
                {t('addStage')}
              </button>
            </div>
          </div>
        </main>
      </div>

      <AddFlowNodeModal
        agents={agents ?? []}
        initialNode={nodeModalNode}
        open={nodeModalStageIndex !== null}
        providers={providers ?? []}
        tools={tools ?? []}
        onClose={handleCloseNodeModal}
        onSubmit={handleSubmitNode}
      />

      <UnsavedChangesModal guard={leaveGuard} />

      {draggedStageItem && stagePointerY !== null && stageDragPreviewRect ? (
        <DragPreviewCard pointerY={stagePointerY} rect={stageDragPreviewRect}>
          <span
            className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-primary"
            aria-hidden
          >
            drag_indicator
          </span>
          <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-white/10 px-2 text-xs font-semibold leading-none text-white">
            {tFlows('stageLabel', { number: Number(draggedStageItem.id) + 1 })}
          </span>
          <span className="min-w-0 flex-1 truncate text-xs text-textGray">
            {tFlows('nodeCount', { count: draggedStageItem.nodes.length })}
          </span>
        </DragPreviewCard>
      ) : null}
    </div>
  );
}
