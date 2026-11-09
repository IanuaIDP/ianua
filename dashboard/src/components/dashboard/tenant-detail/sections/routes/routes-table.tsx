'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { RouteActionsMenu } from '@/components/dashboard/tenant-detail/sections/routes/route-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useRouteOptions } from '@/hooks/dashboard/use-route-options';
import type { Route, RouteAction, RouteSortDirection, RouteSortField } from '@/types/route';

type RoutesTableProps = {
  canDeleteRoute?: boolean;
  canUpdateRoute?: boolean;
  isLoading?: boolean;
  onEditClick: (route: Route) => void;
  onRouteAction: (route: Route, action: RouteAction) => Promise<void> | void;
  onSortChange: (field: RouteSortField) => void;
  /** Pipeline names by id, so the row can name what a route runs. */
  pipelineNameById?: Record<string, string>;
  routes: Route[];
  /** Service names by id, so the row names the backend rather than its UUID. */
  serviceNameById?: Record<string, string>;
  sortDirection?: RouteSortDirection;
  sortField?: RouteSortField;
};

export function RoutesTable({
  canDeleteRoute = true,
  canUpdateRoute = true,
  isLoading = false,
  onEditClick,
  onRouteAction,
  onSortChange,
  pipelineNameById = {},
  routes,
  serviceNameById = {},
  sortDirection,
  sortField,
}: RoutesTableProps) {
  const t = useTranslations('dashboard.routes');
  const { pathRewriteLabel, policyLabel } = useRouteOptions();
  const columns: DashboardTableColumn<RouteSortField>[] = [
    { className: 'w-[13%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[13%]', label: t('columns.path') },
    { className: 'w-[9%]', label: t('columns.methods') },
    { className: 'w-[16%]', label: t('columns.service') },
    { className: 'w-[11%]', label: t('columns.pipeline') },
    { className: 'w-[13%]', label: t('columns.policy') },
    { className: 'w-[11%]', label: t('columns.forwardedPath') },
    { className: 'w-[7%]', label: t('columns.status'), sortField: 'status' },
    { className: 'w-[7%]', label: t('columns.priority'), sortField: 'priority' },
  ];
  const badgeClassName =
    'inline-flex h-5 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white';

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={routes.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-230"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {routes.map((route) => (
        <tr key={route.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{route.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{route.pathPattern}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <span className={badgeClassName}>
              {route.methods.join(', ').toUpperCase() || t('noMethods')}
            </span>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{serviceNameById[route.serviceId] ?? '—'}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pipelineNameById[route.pipelineId] ?? '—'}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <span className={badgeClassName}>{policyLabel(route.policy)}</span>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pathRewriteLabel(route.pathRewrite)}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={route.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{route.priority}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <RouteActionsMenu
              canDelete={canDeleteRoute}
              canUpdate={canUpdateRoute}
              route={route}
              onActionConfirm={onRouteAction}
              onEditClick={onEditClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
