'use client';

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { AllowRegistryModal } from '@/components/dashboard/workflows/sandboxes/allow-registry-modal';
import { useNotification } from '@/components/ui/notifications';
import { TableCellText } from '@/components/ui/table-cell';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getSandboxRegistries,
  removeSandboxRegistry,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { SandboxRegistry } from '@/types/sandbox';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

/** The registries the tenant's company images may come from. */
export default function RegistriesPage() {
  const t = useTranslations('dashboard.sandboxes.registries');
  const tErrors = useTranslations('common.errors');
  const tNav = useNavLabels();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isAllowing, setIsAllowing] = useState(false);
  const canManage = hasPermission('Workflows', 'ConnectAccounts');
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getSandboxRegistries(orgSlug ?? '', tenantSlug),
    queryKey: ['sandbox-registries', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const sandboxesPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'sandboxes',
    'sandboxes',
  );
  const headerTrail = isTenantView
    ? [{ href: sandboxesPath, icon: 'terminal' }, { title: t('title') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview'),
          title: companyDisplayName,
        },
        { href: sandboxesPath, title: tNav.label('Sandboxes') },
        { title: t('title') },
      ];
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[46%]', label: t('columns.host') },
    { className: 'w-[30%]', label: t('columns.login') },
    { className: 'w-[24%]', label: t('columns.allowed') },
  ];

  async function refreshList() {
    await queryClient.invalidateQueries({ queryKey: ['sandbox-registries', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function handleRemove(registry: SandboxRegistry) {
    await removeSandboxRegistry(orgSlug ?? '', tenantSlug, registry.id);
    await refreshList();
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Sandboxes"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <DashboardDataCard
            actionLabel={canManage ? t('allowAction') : undefined}
            description={t('description')}
            errorMessage={errorMessage}
            title={t('title')}
            onActionClick={() => setIsAllowing(true)}
          >
            <DashboardTableShell
              columns={columns}
              emptyMessage={t('empty')}
              hasActionsColumn
              isEmpty={(data?.length ?? 0) === 0}
              isLoading={isLoading}
              loadingMessage={t('loading')}
              minWidthClassName="min-w-160"
              onSortChange={() => {}}
            >
              {(data ?? []).map((registry) => (
                <tr key={registry.id} className="group h-11 transition hover:bg-hoverBg">
                  <td className="px-4 py-2">
                    <TableCellText className="font-semibold text-white">
                      {registry.host}
                    </TableCellText>
                  </td>
                  <td className="px-4 py-2">
                    <TableCellText>
                      {registry.login === 'anonymous'
                        ? t('anonymous')
                        : t('passwordLogin', { username: registry.username ?? '' })}
                    </TableCellText>
                  </td>
                  <td className="px-4 py-2">
                    <TableCellText>{formatBackendDateTime(registry.createdAt)}</TableCellText>
                  </td>
                  <DashboardTableActionsCell className="px-4 py-2">
                    <div className="flex justify-end">
                      <DashboardActionsMenu
                        actionLabels={{ Remove: t('remove') }}
                        actions={canManage ? ['Remove' as const] : []}
                        ariaLabel={t('menu', { host: registry.host })}
                        getActionErrorMessage={(actionError) =>
                          getApiErrorMessage(actionError, t('removeFailed'))
                        }
                        getActionSuccessMessage={() => t('removed')}
                        modalContentByAction={{
                          Remove: {
                            description: t('removeDescription', { host: registry.host }),
                            primaryActionLabel: t('remove'),
                            title: t('removeTitle', { host: registry.host }),
                            warningTone: 'danger',
                          },
                        }}
                        onActionConfirm={() => handleRemove(registry)}
                      />
                    </div>
                  </DashboardTableActionsCell>
                </tr>
              ))}
            </DashboardTableShell>
          </DashboardDataCard>
        </main>
      </div>

      {isAllowing ? (
        <AllowRegistryModal
          onAllowed={async () => {
            setIsAllowing(false);
            showNotification({ message: t('allow.done'), type: 'success' });
            await refreshList();
          }}
          onClose={() => setIsAllowing(false)}
        />
      ) : null}
    </div>
  );
}
