'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { DomainActionsMenu } from '@/components/dashboard/tenant-detail/sections/domains/domain-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { Domain, DomainAction, DomainSortDirection, DomainSortField } from '@/types/domain';
import { getDomainManagementPath, getDomainPath } from '@/utils/dashboard-routes';

type DomainsTableProps = {
  canDeleteDomain?: boolean;
  canTransferDomain?: boolean;
  canUpdateDomain?: boolean;
  domains: Domain[];
  isLoading?: boolean;
  onDomainAction: (domain: Domain, action: DomainAction) => Promise<void> | void;
  onSortChange: (field: DomainSortField) => void;
  onTransfer: (domain: Domain) => void;
  onViewInstructions: (domain: Domain) => void;
  sortDirection?: DomainSortDirection;
  sortField?: DomainSortField;
};

export function DomainsTable({
  canDeleteDomain = true,
  canTransferDomain = true,
  canUpdateDomain = true,
  domains,
  isLoading = false,
  onDomainAction,
  onSortChange,
  onTransfer,
  onViewInstructions,
  sortDirection,
  sortField,
}: DomainsTableProps) {
  const t = useTranslations('dashboard.domains');
  const columns: DashboardTableColumn<DomainSortField>[] = [
    { className: 'w-[36%]', label: t('columns.domain'), sortField: 'domain' },
    { className: 'w-[22%]', label: t('columns.verification'), sortField: 'verification_status' },
    { className: 'w-[18%]', label: t('columns.tls') },
    { className: 'w-[24%]', label: t('columns.created'), sortField: 'created_at' },
  ];
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();

  function goToDomain(domain: Domain) {
    if (!isTenantView) {
      router.push(getDomainManagementPath(tenantSlug, domain.id));
      return;
    }

    if (!orgSlug) {
      return;
    }

    router.push(getDomainPath(orgSlug, tenantSlug, domain.id));
  }

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={domains.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {domains.map((domain) => (
        <tr
          key={domain.id}
          className="group h-11 cursor-pointer transition hover:bg-hoverBg"
          onClick={() => goToDomain(domain)}
        >
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{domain.domain}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={domain.verificationStatus} />
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={domain.tlsStatus} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{domain.created}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <DomainActionsMenu
              canDelete={canDeleteDomain}
              canTransfer={canTransferDomain}
              canUpdate={canUpdateDomain}
              domain={domain}
              onActionConfirm={onDomainAction}
              onTransfer={onTransfer}
              onViewInstructions={onViewInstructions}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
