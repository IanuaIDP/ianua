'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { Tooltip } from '@/components/ui/tooltip';
import { useToolOptions } from '@/hooks/dashboard/use-tool-options';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { FlowNode } from '@/types/flow';
import { cn } from '@/utils/cn';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';
import { getFlowNodeStatusMeta } from '@/utils/flow';

type FlowNodeDetailCardProps = {
  agentName: string;
  isTenantView: boolean;
  node: FlowNode;
  orgSlug: string | undefined;
  providerModel: string | null;
  tenantSlug: string;
};

const chipClassName =
  'inline-flex shrink-0 items-center gap-1 rounded-md bg-surfaceChip px-2 py-1 text-xs font-medium text-white hover:bg-borderGray';

function getRunDisplayId(runId: string) {
  return `run-${runId.slice(-4)}`;
}

export function FlowNodeDetailCard({
  agentName,
  isTenantView,
  node,
  orgSlug,
  providerModel,
  tenantSlug,
}: FlowNodeDetailCardProps) {
  const t = useTranslations('dashboard.flows.node');
  const { actionClassLabel } = useToolOptions();
  const purposeLabel = node.purpose.map(actionClassLabel).join(', ');
  const tStatus = useLooseTranslations('dashboard.status');
  const statusMeta = getFlowNodeStatusMeta(node.status);
  const runHref = isTenantView
    ? orgSlug
      ? `${getAgentPath(orgSlug, tenantSlug, node.agentId)}/runs`
      : undefined
    : `${getAgentManagementPath(tenantSlug, node.agentId)}/runs`;

  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-lg border border-borderGray bg-appBg/40 p-3 text-left">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex min-w-32 items-center gap-2">
          <p className="min-w-0 truncate text-sm font-semibold text-white">{agentName}</p>
          <span
            className={cn(
              'inline-flex h-5 shrink-0 items-center rounded-md px-1.5 text-[10px] font-medium leading-none',
              statusMeta.className,
            )}
          >
            {tStatus.has(statusMeta.label) ? tStatus(statusMeta.label) : statusMeta.label}
          </span>
          {node.status === 'Completed' && node.outputExposure !== 'Public' ? (
            <DashboardStatusBadge status={node.outputExposure} />
          ) : null}
        </div>
        {node.runId && runHref ? (
          <Link
            href={runHref}
            onClick={(event) => event.stopPropagation()}
            className="inline-flex shrink-0 items-center gap-1 rounded-md bg-surfaceChip px-1.5 py-1 text-[10px] font-medium text-white transition hover:bg-hoverBg"
          >
            <span className="material-symbols-rounded text-xs!" aria-hidden>
              play_circle
            </span>
            {getRunDisplayId(node.runId)}
          </Link>
        ) : node.runId ? (
          <span className="inline-flex shrink-0 items-center gap-1 text-[10px] text-textGray">
            <span className="material-symbols-rounded text-xs!" aria-hidden>
              play_circle
            </span>
            {getRunDisplayId(node.runId)}
          </span>
        ) : null}
      </div>

      <p className="truncate text-xs text-textGray">{node.goal || t('noGoal')}</p>

      <div className="flex flex-wrap items-center gap-1.5">
        {node.purpose.length > 0 ? (
          <Tooltip title={t('actionClasses')} content={purposeLabel} side="bottom-right">
            <span className={cn(chipClassName, 'max-w-32')}>
              <span className="truncate">{purposeLabel}</span>
            </span>
          </Tooltip>
        ) : null}
        <span className={chipClassName}>≤{node.maxSteps}</span>
        {providerModel ? (
          <span className={chipClassName}>
            <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
              neurology
            </span>
            {providerModel}
          </span>
        ) : null}
        {node.toolNames.length > 0 ? (
          <Tooltip title={t('tools')} content={node.toolNames.join(', ')} side="bottom-left">
            <span className={chipClassName}>
              <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
                handyman
              </span>
              {node.toolNames.length}
            </span>
          </Tooltip>
        ) : null}
        {node.approvalClasses.length > 0 ? (
          <Tooltip
            title={t('approvals')}
            content={node.approvalClasses.join(', ')}
            side="bottom-left"
          >
            <span className={chipClassName}>
              <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
                assignment_turned_in
              </span>
              {node.approvalClasses.length}
            </span>
          </Tooltip>
        ) : null}
      </div>

      {node.status === 'Completed' && node.output ? (
        <div className="-mx-3 border-t border-borderGray px-3 pt-2">
          <p className="text-[10px] text-white">{node.output}</p>
        </div>
      ) : null}

      {node.status === 'Failed' && node.errorMessage ? (
        <div className="-mx-3 border-t border-borderGray px-3 pt-2">
          <p className="text-[10px] text-error">{node.errorMessage}</p>
        </div>
      ) : null}
    </div>
  );
}
