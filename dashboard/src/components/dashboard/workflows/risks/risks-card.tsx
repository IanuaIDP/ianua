'use client';

import { useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { IntegrationMark } from '@/components/dashboard/workflows/integration-mark';
import { RaiseRiskModal } from '@/components/dashboard/workflows/risks/raise-risk-modal';
import { TableCellText } from '@/components/ui/table-cell';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getWorkflowIntegrations,
  getWorkflowOperations,
  getWorkflowRisks,
  removeWorkflowRisk,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { WorkflowRisk } from '@/types/workflow-risk';
import { formatBackendDateTime } from '@/utils/date';

type RiskAction = 'Change' | 'Remove';

/** Operations the tenant treats as riskier than their integration says. */
export function RisksCard({ tabs }: { tabs: ReactNode }) {
  const t = useTranslations('dashboard.workflowRisks');
  const tEffect = useLooseTranslations('dashboard.workflowRisks.effects');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const [modalRisk, setModalRisk] = useState<WorkflowRisk | 'new' | null>(null);
  const hasOrg = Boolean(orgSlug && tenantSlug);
  const canUpdate = hasPermission('Workflows', 'Update');
  const canRemove = hasPermission('Workflows', 'Manage');
  const { data, error, isLoading } = useQuery({
    enabled: hasOrg,
    queryFn: () => getWorkflowRisks(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-risks', orgSlug, tenantSlug],
  });
  const { data: integrations } = useQuery({
    enabled: hasOrg,
    queryFn: () => getWorkflowIntegrations(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-integrations', orgSlug, tenantSlug],
  });
  const { data: operations } = useQuery({
    enabled: hasOrg,
    queryFn: () => getWorkflowOperations(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-operations', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[34%]', label: t('columns.step') },
    { className: 'w-[36%]', label: t('columns.effect') },
    { className: 'w-[30%]', label: t('columns.changed') },
  ];
  const integrationByKey = new Map((integrations ?? []).map((item) => [item.key, item]));
  const actions: RiskAction[] = [
    ...(canUpdate ? (['Change'] as const) : []),
    ...(canRemove ? (['Remove'] as const) : []),
  ];

  function operationTitle(risk: WorkflowRisk) {
    const operation = operations?.find(
      (item) => item.integration === risk.integration && item.operation === risk.operation,
    );

    return operation?.title ?? risk.operation;
  }

  async function handleRemove(risk: WorkflowRisk) {
    await removeWorkflowRisk(orgSlug ?? '', tenantSlug, risk.id);
    await queryClient.invalidateQueries({ queryKey: ['workflow-risks', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={canUpdate ? t('raise') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        tabs={tabs}
        title={t('title')}
        onActionClick={() => setModalRisk('new')}
      >
        <DashboardTableShell
          columns={columns}
          emptyMessage={t('empty')}
          hasActionsColumn
          isEmpty={(data?.length ?? 0) === 0}
          isLoading={isLoading}
          loadingMessage={t('loading')}
          minWidthClassName="min-w-190"
          onSortChange={() => {}}
        >
          {(data ?? []).map((risk) => {
            const integration = integrationByKey.get(risk.integration);

            return (
              <tr key={risk.id} className="group h-11 transition hover:bg-hoverBg">
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2.5">
                    {integration ? <IntegrationMark integration={integration} /> : null}
                    <div className="min-w-0">
                      <TableCellText className="font-semibold text-white">
                        {operationTitle(risk)}
                      </TableCellText>
                      <p className="text-[10px] text-textGray">
                        {integration?.title ?? risk.integration}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>
                    {tEffect.has(risk.effect) ? tEffect(risk.effect) : risk.effect}
                  </TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>{formatBackendDateTime(risk.updatedAt)}</TableCellText>
                </td>
                <DashboardTableActionsCell className="px-4 py-2">
                  <div className="flex justify-end">
                    <DashboardActionsMenu<RiskAction>
                      actionLabels={{ Change: t('change'), Remove: t('remove') }}
                      actions={actions}
                      ariaLabel={t('menu', { name: operationTitle(risk) })}
                      customActions={['Change']}
                      getActionErrorMessage={(actionError) =>
                        getApiErrorMessage(actionError, t('removeFailed'))
                      }
                      getActionSuccessMessage={() => t('removed')}
                      modalContentByAction={{
                        Remove: {
                          description: t('removeDescription', { name: operationTitle(risk) }),
                          primaryActionLabel: t('remove'),
                          title: t('removeTitle'),
                          warningTone: 'danger',
                        },
                      }}
                      onActionConfirm={() => handleRemove(risk)}
                      onCustomAction={() => setModalRisk(risk)}
                    />
                  </div>
                </DashboardTableActionsCell>
              </tr>
            );
          })}
        </DashboardTableShell>
      </DashboardDataCard>

      {modalRisk !== null ? (
        <RaiseRiskModal
          integrations={integrations ?? []}
          operations={operations ?? []}
          risk={modalRisk === 'new' ? null : modalRisk}
          risks={data ?? []}
          onClose={() => setModalRisk(null)}
        />
      ) : null}
    </>
  );
}
