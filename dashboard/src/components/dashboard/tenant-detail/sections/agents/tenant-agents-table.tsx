'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantAgentActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/tenant-agent-actions-menu';
import { TableCellStack, TableCellText } from '@/components/ui/table-cell';
import { useAgentText } from '@/hooks/dashboard/use-agent-text';
import type {
  TenantAgent,
  TenantAgentAction,
  TenantAgentSortDirection,
  TenantAgentSortField,
} from '@/types/tenant-agent';
import type { TenantUser } from '@/types/tenant-user';
import { getBadgeColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { shortId } from '@/utils/tenant-agent';

type TenantAgentsTableProps = {
  agents: TenantAgent[];
  agentsById: Map<string, TenantAgent>;
  canDeleteAgent?: boolean;
  canUpdateAgent?: boolean;
  isLoading?: boolean;
  onAgentAction: (agent: TenantAgent, action: TenantAgentAction) => Promise<void> | void;
  onAgentClick?: (agent: TenantAgent) => void;
  onEditClick: (agent: TenantAgent) => void;
  onSortChange: (field: TenantAgentSortField) => void;
  sortDirection?: TenantAgentSortDirection;
  sortField?: TenantAgentSortField;
  usersById: Map<string, TenantUser>;
};

export function TenantAgentsTable({
  agents,
  agentsById,
  canDeleteAgent = true,
  canUpdateAgent = true,
  isLoading = false,
  onAgentAction,
  onAgentClick,
  onEditClick,
  onSortChange,
  sortDirection,
  sortField,
  usersById,
}: TenantAgentsTableProps) {
  const t = useTranslations('dashboard.agents');
  const { ownerDisplay } = useAgentText();
  const columns: DashboardTableColumn<TenantAgentSortField>[] = [
    { className: 'w-[24%]', label: t('columns.agent'), sortField: 'name' },
    { className: 'w-[10%]', label: t('columns.status'), sortField: 'status' },
    { className: 'w-[20%]', label: t('columns.owner') },
    { className: 'w-[14%]', label: t('columns.attestation') },
    { className: 'w-[16%]', label: t('columns.created'), sortField: 'created_at' },
    { className: 'w-[16%]', label: t('columns.updated'), sortField: 'updated_at' },
  ];
  return (
    <DashboardTableShell
      className="mt-4"
      columns={columns}
      hasActionsColumn
      isEmpty={agents.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-230"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {agents.map((agent) => {
        const owner = ownerDisplay(agent.owner, usersById, agentsById);
        const hasAttestationPolicy = agent.attestationMethods.length > 0;

        return (
          <tr
            key={agent.id}
            className={cn(
              'group h-11 transition hover:bg-hoverBg',
              onAgentClick && 'cursor-pointer',
            )}
            onClick={() => onAgentClick?.(agent)}
          >
            <td className="px-4 py-2">
              <TableCellStack
                primary={agent.name}
                primaryClassName="font-semibold text-white"
                secondary={shortId(agent.id)}
                secondaryClassName="text-[10px] font-medium text-textGray"
              />
            </td>
            <td className="px-4 py-2">
              <DashboardStatusBadge status={agent.standing} />
            </td>
            <td className="px-4 py-2">
              <div className="flex min-w-0 items-center gap-3">
                <span
                  className={cn(
                    'flex size-6 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                    getBadgeColorClass(owner.seed),
                  )}
                >
                  {owner.initial}
                </span>
                <TableCellStack
                  primary={owner.name}
                  primaryClassName="font-semibold text-white"
                  secondary={owner.secondary}
                  secondaryClassName="text-[10px] font-medium text-textGray"
                />
              </div>
            </td>
            <td className="px-4 py-2">
              {hasAttestationPolicy ? (
                <span className="inline-flex items-center rounded-md bg-surfaceInset px-1.5 py-0.5 text-[10px] font-medium leading-none text-white">
                  {agent.attestationMethods.map((method) => method.toUpperCase()).join(', ')}
                </span>
              ) : (
                <span className="text-xs font-medium text-textGray">{t('notConfigured')}</span>
              )}
            </td>
            <td className="px-4 py-2">
              <TableCellText>{agent.created}</TableCellText>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{agent.updated}</TableCellText>
            </td>
            <DashboardTableActionsCell>
              <TenantAgentActionsMenu
                agent={agent}
                canDelete={canDeleteAgent}
                canUpdate={canUpdateAgent}
                onActionConfirm={onAgentAction}
                onEditClick={onEditClick}
              />
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
