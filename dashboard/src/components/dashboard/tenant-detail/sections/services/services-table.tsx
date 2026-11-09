'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ServiceActionsMenu } from '@/components/dashboard/tenant-detail/sections/services/service-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useServiceOptions } from '@/hooks/dashboard/use-service-options';
import type {
  GatewayService,
  GatewayServiceAction,
  GatewayServiceSortDirection,
  GatewayServiceSortField,
} from '@/types/gateway-service';
import { formatServiceTarget } from '@/utils/service';

type ServicesTableProps = {
  canDeleteService?: boolean;
  canUpdateService?: boolean;
  isLoading?: boolean;
  onEditClick: (service: GatewayService) => void;
  onServiceAction: (service: GatewayService, action: GatewayServiceAction) => Promise<void> | void;
  onSortChange: (field: GatewayServiceSortField) => void;
  services: GatewayService[];
  sortDirection?: GatewayServiceSortDirection;
  sortField?: GatewayServiceSortField;
};

export function ServicesTable({
  canDeleteService = true,
  canUpdateService = true,
  isLoading = false,
  onEditClick,
  onServiceAction,
  onSortChange,
  services,
  sortDirection,
  sortField,
}: ServicesTableProps) {
  const t = useTranslations('dashboard.services');
  const { stickySessionLabel } = useServiceOptions();
  const columns: DashboardTableColumn<GatewayServiceSortField>[] = [
    { className: 'w-[18%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[26%]', label: t('columns.target') },
    { className: 'w-[10%]', label: t('columns.backends') },
    { className: 'w-[10%]', label: t('columns.timeout') },
    { className: 'w-[10%]', label: t('columns.probes') },
    { className: 'w-[14%]', label: t('columns.config') },
    { className: 'w-[8%]', label: t('columns.status') },
  ];
  const badgeClassName =
    'inline-flex h-5 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white';

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={services.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-230"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {services.map((service) => (
        <tr key={service.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{service.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{formatServiceTarget(service)}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{service.additionalBackends.length + 1}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{t('seconds', { seconds: service.timeoutSecs })}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText className={service.healthCheckEnabled ? undefined : 'text-textGray'}>
              {service.healthCheckEnabled ? service.healthCheckPath : t('probesOff')}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            <div className="flex flex-wrap items-center gap-1">
              {service.stickySession ? (
                <span className={badgeClassName}>
                  {t('stickyBadge', { kind: stickySessionLabel(service.stickySession) })}
                </span>
              ) : null}
              {service.requireClientCertificate ? (
                <span className={badgeClassName}>mTLS</span>
              ) : null}
              {!service.expectedAudience ? (
                <span className={badgeClassName}>{t('publicOnly')}</span>
              ) : null}
            </div>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={service.status} />
          </td>
          <DashboardTableActionsCell>
            <ServiceActionsMenu
              canDelete={canDeleteService}
              canUpdate={canUpdateService}
              service={service}
              onActionConfirm={onServiceAction}
              onEditClick={onEditClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
