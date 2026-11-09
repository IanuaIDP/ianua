'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ModelProviderActionsMenu } from '@/components/dashboard/tenant-detail/sections/model-providers/model-provider-actions-menu';
import { TestStatus } from '@/components/dashboard/tenant-detail/sections/model-providers/test-status';
import { TableCellText } from '@/components/ui/table-cell';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import type {
  ModelProvider,
  ModelProviderAction,
  ModelProviderTestState,
} from '@/types/model-provider';
import { getBadgeSoftColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { deriveTestState } from '@/utils/model-provider';

type ModelProvidersTableProps = {
  isLoading?: boolean;
  onClearance: (provider: ModelProvider) => void;
  onEmbeddingModel: (provider: ModelProvider) => void;
  onProviderAction: (provider: ModelProvider, action: ModelProviderAction) => Promise<void> | void;
  onTest: (provider: ModelProvider) => void;
  providers: ModelProvider[];
  testStateByProviderId: Record<string, ModelProviderTestState | undefined>;
};

export function ModelProvidersTable({
  isLoading = false,
  onClearance,
  onEmbeddingModel,
  onProviderAction,
  onTest,
  providers,
  testStateByProviderId,
}: ModelProvidersTableProps) {
  const t = useTranslations('dashboard.modelProviders');
  const tKinds = useLooseTranslations('dashboard.modelProviders.kinds');
  const { hasPermission } = useTenantPermissions();
  const canManage = hasPermission('Agents', 'Manage');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[68%]', label: t('title') },
    { className: 'w-[32%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={providers.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {providers.map((provider) => {
        const testState = testStateByProviderId[provider.id] ?? deriveTestState(provider);

        return (
          <tr key={provider.id} className="group transition hover:bg-hoverBg">
            <td className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-white">{provider.name}</span>
                <span className="inline-flex h-5 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
                  {tKinds.has(provider.kind) ? tKinds(provider.kind) : provider.kind}
                </span>
                <span
                  className={cn(
                    'inline-flex h-5 items-center rounded-md px-1.5 text-[10px] font-medium leading-none',
                    getBadgeSoftColorClass(provider.model),
                  )}
                >
                  {provider.model}
                </span>
              </div>
              <TableCellText className="mt-1 w-auto max-w-96 font-mono text-[10px] text-textGray">
                {provider.endpoint}
              </TableCellText>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px]">
                <span>
                  <span className="text-textGray mr-1">{t('key')}</span>
                  <span className="text-white">
                    {provider.hasCredential ? t('keyStored') : t('keyless')}
                  </span>
                </span>
                <span className="inline-block h-3.5 w-px bg-borderGray" aria-hidden />
                <span className="flex items-center gap-1">
                  <span className="text-textGray">{t('test')}</span>
                  <TestStatus testState={testState} />
                </span>
                <span className="inline-block h-3.5 w-px bg-borderGray" aria-hidden />
                <span>
                  <span className="text-textGray mr-1">{t('clearance.label')}</span>
                  <span className="text-white">{provider.clearance ?? 'Public'}</span>
                </span>
                {provider.embeddingModel ? (
                  <>
                    <span className="inline-block h-3.5 w-px bg-borderGray" aria-hidden />
                    <span>
                      <span className="text-textGray mr-1">{t('embeddings.label')}</span>
                      <span className="text-white">{provider.embeddingModel}</span>
                    </span>
                  </>
                ) : null}
              </div>
            </td>
            <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
              <div className="flex items-center justify-end gap-3">
                <DashboardStatusBadge status={provider.status} />
                {provider.status !== 'Disabled' && canManage ? (
                  <button
                    type="button"
                    disabled={testState?.status === 'pending'}
                    onClick={() => onTest(provider)}
                    className="inline-flex h-7 items-center gap-1.5 rounded-md border border-borderGray px-2.5 text-[10px] font-medium text-white transition hover:bg-hoverBg disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <span className="material-symbols-rounded text-sm!" aria-hidden>
                      sync
                    </span>
                    {testState?.status === 'pending' ? t('testing') : t('test')}
                  </button>
                ) : null}
                <ModelProviderActionsMenu
                  provider={provider}
                  onActionConfirm={onProviderAction}
                  onClearance={onClearance}
                  onEmbeddingModel={onEmbeddingModel}
                />
              </div>
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
