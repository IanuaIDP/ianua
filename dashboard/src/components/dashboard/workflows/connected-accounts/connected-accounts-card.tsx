'use client';

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import { useNotification } from '@/components/ui/notifications';
import {
  AccountActionsMenu,
  type AccountAction,
} from '@/components/dashboard/workflows/connected-accounts/account-actions-menu';
import {
  AccountChangeModal,
  type AccountChangeKind,
} from '@/components/dashboard/workflows/connected-accounts/account-change-modal';
import { AccountChannelModal } from '@/components/dashboard/workflows/connected-accounts/account-channel-modal';
import { ConnectAccountList } from '@/components/dashboard/workflows/connected-accounts/connect-account-list';
import { IntegrationMark } from '@/components/dashboard/workflows/integration-mark';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useWorkflowCaller } from '@/hooks/dashboard/use-workflow-caller';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  changeWorkflowAccount,
  deriveErrorMessage,
  getApiErrorMessage,
  getWorkflowAccounts,
  getWorkflowIntegrations,
  getWorkflowOperations,
} from '@/lib/api';
import type { WorkflowAccount, WorkflowAccountChange } from '@/types/workflows';
import { formatBackendDateTime } from '@/utils/date';

const instantChange: Record<'Disable' | 'Enable' | 'Keep' | 'Share', WorkflowAccountChange> = {
  Disable: { change: 'disable' },
  Enable: { change: 'enable' },
  Keep: { change: 'keep_to_owner' },
  Share: { change: 'share_with_tenant' },
};

type ChangeTarget = { account: WorkflowAccount; kind: AccountChangeKind };

/** The tenant's accounts on outside services, and what can be done with each. */
export function ConnectedAccountsCard() {
  const t = useTranslations('dashboard.connectedAccounts');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const caller = useWorkflowCaller();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isConnecting, setIsConnecting] = useState(false);
  const [changeTarget, setChangeTarget] = useState<ChangeTarget | null>(null);
  const [channelAccount, setChannelAccount] = useState<WorkflowAccount | null>(null);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    rowsPerPage,
  } = useTableQueryState<never>();
  const canConnect = hasPermission('Workflows', 'ConnectAccounts');
  const hasOrg = Boolean(orgSlug && tenantSlug);
  const { data, error, isLoading } = useQuery({
    enabled: hasOrg,
    queryFn: () => getWorkflowAccounts(orgSlug ?? '', tenantSlug, { after, limit: rowsPerPage }),
    queryKey: ['workflow-accounts', orgSlug, tenantSlug, after, rowsPerPage],
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
  const connectable = (integrations ?? []).filter((integration) =>
    (operations ?? []).some(
      (operation) => operation.integration === integration.key && operation.needsAccount,
    ),
  );
  const integrationByKey = new Map(
    (integrations ?? []).map((integration) => [integration.key, integration]),
  );
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[40%]', label: t('columns.account') },
    { className: 'w-[22%]', label: t('columns.sharing') },
    { className: 'w-[16%]', label: t('columns.status') },
    { className: 'w-[22%]', label: t('columns.connected') },
  ];

  async function runInstant(account: WorkflowAccount, action: keyof typeof instantChange) {
    await changeWorkflowAccount(orgSlug ?? '', tenantSlug, account.id, instantChange[action]);
    await queryClient.invalidateQueries({ queryKey: ['workflow-accounts', orgSlug, tenantSlug] });
  }

  function handleAction(account: WorkflowAccount, action: AccountAction) {
    if (action === 'Events') {
      setChannelAccount(account);
      return;
    }

    if (action === 'Rename' || action === 'Replace' || action === 'Limit') {
      setChangeTarget({ account, kind: action });
    }
  }

  async function handleConfirm(account: WorkflowAccount, action: AccountAction) {
    if (action in instantChange) {
      await runInstant(account, action as keyof typeof instantChange);
    }
  }

  return (
    <>
      {isConnecting ? (
        <ConnectAccountList integrations={connectable} onClose={() => setIsConnecting(false)} />
      ) : null}

      <DashboardDataCard
        actionLabel={t('connectAction')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            itemCount={data?.items.length ?? 0}
            nextCursor={data?.nextCursor ?? null}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="workflow-accounts-rows-per-page"
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canConnect && !isConnecting ? () => setIsConnecting(true) : undefined}
      >
        <DashboardTableShell
          columns={columns}
          emptyMessage={t('empty')}
          hasActionsColumn
          isEmpty={(data?.items.length ?? 0) === 0}
          isLoading={isLoading}
          loadingMessage={t('loading')}
          minWidthClassName="min-w-190"
          onSortChange={() => {}}
        >
          {(data?.items ?? []).map((account) => {
            const integration = integrationByKey.get(account.integration);

            return (
              <tr key={account.id} className="group h-11 transition hover:bg-hoverBg">
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2.5">
                    {integration ? <IntegrationMark integration={integration} /> : null}
                    <div className="min-w-0">
                      <TableCellText className="font-semibold text-white">
                        {account.name}
                      </TableCellText>
                      <p className="text-[10px] text-textGray">
                        {integration?.title ?? account.integration}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>
                    {account.sharing === 'tenant' ? t('sharingTenant') : t('sharingOwner')}
                  </TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>
                    {account.status === 'disabled' ? t('statusDisabled') : t('statusEnabled')}
                  </TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>{formatBackendDateTime(account.createdAt)}</TableCellText>
                </td>
                <DashboardTableActionsCell className="px-4 py-2">
                  <div className="flex justify-end">
                    <AccountActionsMenu
                      account={account}
                      canManage={canConnect}
                      isOwner={account.owner === caller}
                      onAction={(action) => handleAction(account, action)}
                      onConfirm={(action) => handleConfirm(account, action)}
                    />
                  </div>
                </DashboardTableActionsCell>
              </tr>
            );
          })}
        </DashboardTableShell>
      </DashboardDataCard>

      {channelAccount ? (
        <AccountChannelModal account={channelAccount} onClose={() => setChannelAccount(null)} />
      ) : null}

      {changeTarget ? (
        <AccountChangeModal
          account={changeTarget.account}
          kind={changeTarget.kind}
          onClose={() => setChangeTarget(null)}
          onDone={(message) => {
            setChangeTarget(null);
            showNotification({ message, type: 'success' });
          }}
          operations={operations ?? []}
        />
      ) : null}
    </>
  );
}
