'use client';

import { Fragment, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { DelegationActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/delegations/delegation-actions-menu';
import { DelegationBudgetBadge } from '@/components/dashboard/tenant-detail/sections/agents/delegations/delegation-budget-badge';
import { DelegationResourceActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/delegations/delegation-resource-actions-menu';
import { GrantResourceAccessModal } from '@/components/dashboard/tenant-detail/sections/agents/delegations/grant-resource-access-modal';
import { Tooltip } from '@/components/ui/tooltip';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import type { GrantResourceAccessInput } from '@/schemas/delegation-schemas';
import type { Delegation, DelegationAction } from '@/types/delegation';
import { getBadgeColorClass, getBadgeSoftColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { formatBackendDateTime } from '@/utils/date';
import { getInitials } from '@/utils/initials';
import { getCapabilityBadges, getDelegationPurpose } from '@/utils/delegation';

type DelegationsTableProps = {
  agentName?: string;
  appNames: Record<string, string>;
  canRevoke?: boolean;
  delegations: Delegation[];
  isGrantingResource?: boolean;
  isLoading?: boolean;
  onDelegationAction: (delegation: Delegation, action: DelegationAction) => Promise<void> | void;
  onGrantResource: (delegationId: string, payload: GrantResourceAccessInput) => Promise<unknown>;
  onRevokeResource: (
    delegationId: string,
    relation: string,
    resource: string,
  ) => Promise<void> | void;
};

export function DelegationsTable({
  agentName,
  appNames,
  canRevoke = true,
  delegations,
  isGrantingResource = false,
  isLoading = false,
  onDelegationAction,
  onGrantResource,
  onRevokeResource,
}: DelegationsTableProps) {
  const t = useTranslations('dashboard.delegations');
  const { chainLabel, driftMode, title: delegationTitle } = useDelegationText();
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('table.title') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [grantResourceDelegationId, setGrantResourceDelegationId] = useState<string | null>(null);

  async function handleGrantResourceSubmit(data: GrantResourceAccessInput) {
    if (!grantResourceDelegationId) {
      return;
    }

    try {
      await onGrantResource(grantResourceDelegationId, data);
      setGrantResourceDelegationId(null);
    } catch {
      // Error is already surfaced via notification by the caller; keep the
      // modal open so the person can fix the input and retry.
    }
  }

  return (
    <>
      <DashboardTableShell
        columns={columns}
        isEmpty={delegations.length === 0}
        isLoading={isLoading}
        loadingMessage={t('table.loading')}
        minWidthClassName="min-w-220"
        onSortChange={() => {}}
      >
        {delegations.map((delegation) => {
          const isExpanded = expandedId === delegation.delegationId;
          const capabilityBadges = getCapabilityBadges(delegation);
          const purpose = getDelegationPurpose(delegation);
          const metaSegments: ReactNode[] = [
            delegation.task ? (
              <span key="task" className="flex items-center gap-1.5">
                {t('table.boundToTask')}
                <span className="inline-flex h-5 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
                  {delegation.task}
                </span>
              </span>
            ) : null,
            <span key="expires">
              {t('table.expires')}
              <span className="inline-flex h-5 items-center px-1.5 text-[10px] font-medium leading-none text-white">
                {formatBackendDateTime(delegation.expiresAt)}
              </span>
            </span>,
            delegation.maxDepth ? (
              <span key="depth" className="flex items-center gap-1.5">
                {t('table.depth')}
                <span className="inline-flex h-5 items-center text-[10px] font-medium leading-none text-white">
                  {delegation.maxDepth}
                </span>
              </span>
            ) : null,
            delegation.budget ? (
              <span key="budget" className="flex items-center gap-1.5">
                {t('table.budget')}
                <DelegationBudgetBadge budget={delegation.budget} />
              </span>
            ) : null,
          ].filter((segment) => segment !== null);

          return (
            <Fragment key={delegation.delegationId}>
              <tr className={cn('group transition hover:bg-hoverBg', isExpanded && 'border-b-0')}>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-4">
                    <button
                      type="button"
                      aria-label={isExpanded ? t('table.collapse') : t('table.expand')}
                      onClick={() => setExpandedId(isExpanded ? null : delegation.delegationId)}
                      className={cn(
                        'flex size-5 shrink-0 items-center justify-center rounded transition hover:bg-hoverBg hover:text-white',
                        isExpanded ? 'text-primary' : 'text-textGray',
                      )}
                    >
                      <span
                        className={cn(
                          'material-symbols-rounded text-base! transition-transform',
                          isExpanded && 'rotate-90',
                        )}
                        aria-hidden
                      >
                        chevron_right
                      </span>
                    </button>
                    <div className="min-w-0">
                      <p className="truncate font-semibold text-white">
                        {delegationTitle(delegation)}
                      </p>
                      {purpose ? (
                        <p className="mt-1 truncate text-[10px] text-textGray">{purpose}</p>
                      ) : null}
                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-textGray">
                        {metaSegments.map((segment, segmentIndex) => (
                          <Fragment key={segmentIndex}>
                            {segmentIndex > 0 ? (
                              <span className="inline-block h-3.5 w-px bg-borderGray" aria-hidden />
                            ) : null}
                            {segment}
                          </Fragment>
                        ))}
                      </div>
                    </div>
                  </div>
                </td>
                <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
                  <div className="flex items-center justify-end gap-3">
                    <DashboardStatusBadge status={delegation.status} />
                    <DelegationActionsMenu
                      canRevoke={canRevoke}
                      delegation={delegation}
                      onActionConfirm={onDelegationAction}
                    />
                  </div>
                </DashboardTableActionsCell>
              </tr>
              {isExpanded ? (
                <tr>
                  <td colSpan={2} className="bg-cardBg px-4 pb-4">
                    <div className="ml-8 rounded-lg border border-borderGray bg-surfaceChip text-xs">
                      <div className="flex flex-col gap-2.5 p-3">
                        <div className="flex items-center gap-3">
                          <p className="w-24 shrink-0 text-textGray">{t('table.driftMode')}</p>
                          <p className="font-medium text-white">{driftMode(delegation.intent)}</p>
                        </div>
                        <div className="flex items-center gap-3">
                          <p className="w-24 shrink-0 text-textGray">{t('table.path')}</p>
                          <p className="font-mono inline-flex h-5 items-center bg-white/15 rounded-md px-1.5 text-[10px] font-medium leading-none text-white">
                            {delegation.resourceScope?.length
                              ? delegation.resourceScope.join(', ')
                              : '—'}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          <p className="w-24 shrink-0 text-textGray">{t('table.apps')}</p>
                          <p className="inline-flex h-5 items-center bg-white/15 rounded-md px-1.5 text-[10px] font-medium leading-none text-white">
                            {delegation.apps?.length
                              ? delegation.apps.map((id) => appNames[id] ?? id).join(', ')
                              : '—'}
                          </p>
                        </div>
                        <div className="flex items-start gap-3">
                          <p className="w-24 shrink-0 pt-0.5 text-textGray">
                            {t('table.capabilities')}
                          </p>
                          <div className="flex flex-wrap gap-1.5">
                            {capabilityBadges.length ? (
                              capabilityBadges.map((badge) => (
                                <span
                                  key={badge}
                                  className="inline-flex items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white"
                                >
                                  {badge}
                                </span>
                              ))
                            ) : (
                              <span className="text-textGray">{t('table.noCapabilities')}</span>
                            )}
                          </div>
                        </div>

                        {delegation.requiresApproval || delegation.senderConstrained ? (
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-textGray">
                            {delegation.requiresApproval ? (
                              <span>{t('table.requiresApproval')}</span>
                            ) : null}
                            {delegation.senderConstrained ? (
                              <span>{t('table.senderConstrained')}</span>
                            ) : null}
                          </div>
                        ) : null}
                      </div>

                      <div className="border-t border-borderGray p-3">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray">
                            {t('table.chain')}
                          </p>
                          {delegation.parent ? (
                            <Tooltip
                              content={t('table.parent', { id: delegation.parent.slice(0, 8) })}
                              side="top"
                            >
                              <p className="text-[10px] text-textGray">{chainLabel(delegation)}</p>
                            </Tooltip>
                          ) : (
                            <p className="text-[10px] text-textGray">{chainLabel(delegation)}</p>
                          )}
                        </div>
                        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-borderGray p-3 text-[10px]">
                          <span className="flex items-center gap-1.5">
                            <span
                              className={cn(
                                'flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                                getBadgeColorClass(delegation.delegator.id),
                              )}
                            >
                              {getInitials(
                                delegation.delegator.displayName ?? delegation.delegator.id,
                              )}
                            </span>
                            <span className={delegation.delegator.displayName ? '' : 'font-mono'}>
                              <span className="text-white">
                                {delegation.delegator.displayName ??
                                  delegation.delegator.id.slice(0, 8)}
                              </span>
                            </span>
                          </span>
                          <span
                            className="material-symbols-rounded text-sm! text-textGray"
                            aria-hidden
                          >
                            arrow_forward
                          </span>
                          <span className="font-medium text-white">
                            {agentName ?? delegation.delegate.slice(0, 8)}
                          </span>
                          <span
                            className="material-symbols-rounded text-sm! text-textGray"
                            aria-hidden
                          >
                            arrow_forward
                          </span>
                          <span className="font-medium text-white">
                            {delegation.task ?? delegationTitle(delegation)}
                          </span>
                        </div>
                      </div>

                      <div className="border-t border-borderGray p-3">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray">
                            {t('table.grantedResources')}
                          </p>
                          <button
                            type="button"
                            onClick={() => setGrantResourceDelegationId(delegation.delegationId)}
                            className="flex items-center gap-1 text-[10px] font-medium text-primary transition hover:text-primary/80"
                          >
                            <span className="material-symbols-rounded text-sm!" aria-hidden>
                              add
                            </span>
                            {t('table.grantResource')}
                          </button>
                        </div>
                        {delegation.granted.resources.length ? (
                          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                            {delegation.granted.resources.map((resource, index) => (
                              <div
                                key={`${resource.relation}-${resource.resource}-${index}`}
                                className="rounded-md border border-borderGray bg-cardBg px-2.5 py-2"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span
                                    className={cn(
                                      'inline-flex h-5 items-center rounded-md px-1.5 text-[10px] font-medium capitalize leading-none',
                                      getBadgeSoftColorClass(resource.relation),
                                    )}
                                  >
                                    {resource.relation}
                                  </span>
                                  <DelegationResourceActionsMenu
                                    canRevoke={canRevoke}
                                    delegationId={delegation.delegationId}
                                    relation={resource.relation}
                                    resource={resource.resource}
                                    onRevoke={onRevokeResource}
                                  />
                                </div>
                                <p className="mt-1 truncate font-mono text-[10px] text-white">
                                  {resource.resource}
                                </p>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="mt-3 flex items-center justify-center gap-1.5 py-2 text-textGray">
                            <span className="material-symbols-rounded text-sm!" aria-hidden>
                              feedback
                            </span>
                            {t('table.noResources')}
                          </div>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              ) : null}
            </Fragment>
          );
        })}
      </DashboardTableShell>

      <GrantResourceAccessModal
        isSubmitting={isGrantingResource}
        open={grantResourceDelegationId !== null}
        onClose={() => setGrantResourceDelegationId(null)}
        onSubmit={handleGrantResourceSubmit}
      />
    </>
  );
}
