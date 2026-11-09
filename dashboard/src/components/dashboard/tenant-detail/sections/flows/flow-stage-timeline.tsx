'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { FlowNodeDetailCard } from '@/components/dashboard/tenant-detail/sections/flows/flow-node-detail-card';
import type { Flow } from '@/types/flow';
import { cn } from '@/utils/cn';
import { getFlowConnectorLineStyle, getFlowStageStatus } from '@/utils/flow';

type FlowStageTimelineProps = {
  agentNameById: Map<string, string>;
  flow: Flow;
  isTenantView: boolean;
  orgSlug: string | undefined;
  providerModelById: Map<string, string>;
  tenantSlug: string;
};

const markerIconByStatus = {
  Completed: { className: 'text-primary', icon: 'check_circle' },
  Failed: { className: 'text-error', icon: 'cancel' },
  Pending: { className: 'text-textGray', icon: 'fiber_manual_record' },
  Running: { className: 'text-primary', icon: 'adjust' },
};

export function FlowStageTimeline({
  agentNameById,
  flow,
  isTenantView,
  orgSlug,
  providerModelById,
  tenantSlug,
}: FlowStageTimelineProps) {
  const t = useTranslations('dashboard.flows');
  const clampedCurrentStage = Math.min(
    Math.max(flow.currentStage, 0),
    Math.max(flow.stages.length - 1, 0),
  );
  const [expandedStages, setExpandedStages] = useState<Set<number>>(
    () => new Set([clampedCurrentStage]),
  );

  function toggleStage(index: number) {
    setExpandedStages((current) => {
      const next = new Set(current);

      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }

      return next;
    });
  }

  const showCompletedMarker = flow.status === 'Completed';

  return (
    <div className="flex flex-col">
      {flow.stages.map((stageNodes, index) => {
        const stageStatus = getFlowStageStatus(stageNodes);
        const marker = markerIconByStatus[stageStatus];
        const isExpanded = expandedStages.has(index);
        const isLastRow = index === flow.stages.length - 1 && !showCompletedMarker;
        const nextStageNodes = flow.stages[index + 1];
        const nextStageStatus = nextStageNodes
          ? getFlowStageStatus(nextStageNodes)
          : showCompletedMarker
            ? 'Completed'
            : null;

        return (
          <div key={index} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span
                className={cn('material-symbols-rounded text-lg! leading-none', marker.className)}
                aria-hidden
              >
                {marker.icon}
              </span>
              {!isLastRow && nextStageStatus ? (
                <span className="flex flex-1 flex-col">
                  <span
                    className="w-px flex-1"
                    style={getFlowConnectorLineStyle(stageStatus, nextStageStatus)}
                  />
                </span>
              ) : null}
            </div>

            <div className="min-w-0 flex-1 pb-4">
              <div
                className={cn(
                  'rounded-lg border p-3 transition',
                  stageStatus === 'Failed'
                    ? 'border-error'
                    : isExpanded
                      ? 'border-primary'
                      : 'border-borderGray',
                )}
              >
                <button
                  type="button"
                  onClick={() => toggleStage(index)}
                  className="flex w-full items-center justify-between gap-2 text-left"
                >
                  <span className="flex items-center gap-2">
                    <span
                      className={cn(
                        'inline-flex h-5 items-center rounded-md px-2 text-xs font-semibold leading-none',
                        stageStatus === 'Failed'
                          ? 'bg-error/20 text-error'
                          : 'bg-white/10 text-white',
                      )}
                    >
                      {t('stageLabel', { number: index + 1 })}
                    </span>
                    <span className="text-xs text-textGray">
                      {t('nodeCount', { count: stageNodes.length })}
                    </span>
                  </span>
                  <span className="flex items-center gap-2">
                    <DashboardStatusBadge status={stageStatus} />
                    <span
                      className={cn(
                        'material-symbols-rounded text-textGray transition-transform',
                        isExpanded && 'rotate-180',
                      )}
                      aria-hidden
                    >
                      expand_more
                    </span>
                  </span>
                </button>

                {isExpanded ? (
                  <div className="mt-3 grid gap-2.5 sm:grid-cols-3">
                    {stageNodes.map((node) => (
                      <FlowNodeDetailCard
                        key={node.runId ?? `${node.agentId}-${node.goal}`}
                        agentName={agentNameById.get(node.agentId) ?? t('unknownAgent')}
                        isTenantView={isTenantView}
                        node={node}
                        orgSlug={orgSlug}
                        providerModel={providerModelById.get(node.providerId) ?? null}
                        tenantSlug={tenantSlug}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        );
      })}

      {showCompletedMarker ? (
        <div className="flex gap-3">
          <div className="flex flex-col items-center">
            <span
              className="material-symbols-rounded text-lg! leading-none text-primary"
              aria-hidden
            >
              check_circle
            </span>
          </div>
          <p className="min-w-0 flex-1 text-xs font-medium text-primary">{t('completed')}</p>
        </div>
      ) : null}
    </div>
  );
}
