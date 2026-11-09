'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { StreamRouteActionsMenu } from '@/components/dashboard/tenant-detail/sections/routes/stream-route-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useStreamRouteOptions } from '@/hooks/dashboard/use-stream-route-options';
import type {
  StreamRoute,
  StreamRouteAction,
  StreamRouteSortDirection,
  StreamRouteSortField,
} from '@/types/stream-route';

type StreamRoutesTableProps = {
  canDeleteRoute?: boolean;
  canUpdateRoute?: boolean;
  isLoading?: boolean;
  onEditClick: (route: StreamRoute) => void;
  onRouteAction: (route: StreamRoute, action: StreamRouteAction) => Promise<void> | void;
  onSortChange: (field: StreamRouteSortField) => void;
  routes: StreamRoute[];
  sortDirection?: StreamRouteSortDirection;
  sortField?: StreamRouteSortField;
};

export function StreamRoutesTable({
  canDeleteRoute = true,
  canUpdateRoute = true,
  isLoading = false,
  onEditClick,
  onRouteAction,
  onSortChange,
  routes,
  sortDirection,
  sortField,
}: StreamRoutesTableProps) {
  const t = useTranslations('dashboard.ports');
  const { protocolLabel } = useStreamRouteOptions();
  const columns: DashboardTableColumn<StreamRouteSortField>[] = [
    { className: 'w-[18%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[10%]', label: t('columns.port'), sortField: 'listen_port' },
    { className: 'w-[14%]', label: t('columns.protocol') },
    { className: 'w-[22%]', label: t('columns.backends') },
    { className: 'w-[16%]', label: t('columns.answers') },
    { className: 'w-[12%]', label: t('columns.access') },
    { className: 'w-[8%]', label: t('columns.status') },
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
            <TableCellText>{route.listenPort}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <span className={badgeClassName}>{protocolLabel(route.protocol)}</span>
          </td>
          <td className="px-4 py-2">
            <TableCellText>
              {route.backends[0] ? `${route.backends[0].host}:${route.backends[0].port}` : '—'}
              {route.backends.length > 1 ? (
                <span className="ml-1 text-textGray">
                  {t('moreBackends', { count: route.backends.length - 1 })}
                </span>
              ) : null}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText className={route.sni.mode === 'any' ? 'text-textGray' : undefined}>
              {route.sni.mode === 'any' ? t('anyName') : route.sni.names.join(', ')}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            {route.policy === 'mutual_tls' ? (
              <span className={badgeClassName}>{t('clientCertificate')}</span>
            ) : (
              <TableCellText className="text-orange">{t('anyone')}</TableCellText>
            )}
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={route.status} />
          </td>
          <DashboardTableActionsCell>
            <StreamRouteActionsMenu
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
