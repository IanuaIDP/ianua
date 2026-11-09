'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { CreateMemoryModal } from '@/components/dashboard/workflows/memories/create-memory-modal';
import { MemoryDeleteModal } from '@/components/dashboard/workflows/memories/memory-delete-modal';
import { hasLostItsModel } from '@/components/dashboard/workflows/memories/memory-status';
import { ExposureBadge, ToneBadge } from '@/components/dashboard/workflows/workflow-badges';
import { useNotification } from '@/components/ui/notifications';
import { TableCellText } from '@/components/ui/table-cell';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createMemory,
  deriveErrorMessage,
  getApiErrorMessage,
  getMemories,
  getTenantModelProviders,
  restoreMemory,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CreateMemoryFormInput } from '@/schemas/memory-schemas';
import type { Memory } from '@/types/memory';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

type MemoryAction = 'Open' | 'Delete' | 'Bring back';

/** The tenant's memories: named stores of texts that workflows keep and search by meaning. */
export function MemoriesCard() {
  const t = useTranslations('dashboard.memories.list');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const [isCreating, setIsCreating] = useState(false);
  const [deleting, setDeleting] = useState<Memory | null>(null);
  const hasOrg = Boolean(orgSlug && tenantSlug);
  const { data, error, isLoading } = useQuery({
    enabled: hasOrg,
    queryFn: () => getMemories(orgSlug ?? '', tenantSlug),
    queryKey: ['memories', orgSlug, tenantSlug],
  });
  const { data: providers } = useQuery({
    enabled: hasOrg,
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
    retry: false,
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const canDelete = hasPermission('Workflows', 'Delete');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[32%]', label: t('columns.name') },
    { className: 'w-[28%]', label: t('columns.model') },
    { className: 'w-[14%]', label: t('columns.clearance') },
    { className: 'w-[26%]', label: t('columns.status') },
  ];
  const { isPending: isCreateSubmitting, mutate: submitCreate } = useMutation({
    mutationFn: (values: CreateMemoryFormInput) =>
      createMemory(orgSlug ?? '', tenantSlug, {
        clearance: values.clearance,
        name: values.name,
        providerId: values.providerId || null,
      }),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('createFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsCreating(false);
      showNotification({ message: t('created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['memories', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  function memoryPath(memory: Memory) {
    return getTenantScopedPath(
      isTenantView,
      orgSlug,
      tenantSlug,
      `memories/${memory.id}`,
      `memories/${memory.id}`,
    );
  }

  function memoryActions(memory: Memory): MemoryAction[] {
    if (!canDelete) {
      return ['Open'];
    }

    return memory.status === 'deletion_requested' ? ['Open', 'Bring back'] : ['Open', 'Delete'];
  }

  async function handleRestore(memory: Memory) {
    await restoreMemory(orgSlug ?? '', tenantSlug, memory.id);
    await queryClient.invalidateQueries({ queryKey: ['memories', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={hasPermission('Workflows', 'Create') ? t('create') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={() => setIsCreating(true)}
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
          {(data ?? []).map((memory) => (
            <tr
              key={memory.id}
              className="group h-11 cursor-pointer transition hover:bg-hoverBg"
              onClick={() => router.push(memoryPath(memory))}
            >
              <td className="px-4 py-2">
                <TableCellText className="font-semibold text-white">{memory.name}</TableCellText>
              </td>
              <td className="px-4 py-2">
                <TableCellText>
                  {memory.embeddingSource === 'platform'
                    ? t('platformModel', { model: memory.embeddingModel })
                    : memory.embeddingModel}
                </TableCellText>
              </td>
              <td className="px-4 py-2">
                <ExposureBadge exposure={memory.clearance} />
              </td>
              <td className="px-4 py-2">
                {memory.status === 'deletion_requested' ? (
                  <ToneBadge tone="bad">
                    {t('deleting', { at: formatBackendDateTime(memory.deletedAfter ?? '') })}
                  </ToneBadge>
                ) : hasLostItsModel(memory, providers) ? (
                  <ToneBadge tone="warn">{t('modelGone')}</ToneBadge>
                ) : (
                  <ToneBadge tone="ok">{t('active')}</ToneBadge>
                )}
              </td>
              <DashboardTableActionsCell className="px-4 py-2">
                <div className="flex justify-end">
                  <DashboardActionsMenu<MemoryAction>
                    actionLabels={{
                      'Bring back': t('actions.restore'),
                      Delete: t('actions.delete'),
                      Open: t('actions.open'),
                    }}
                    actions={memoryActions(memory)}
                    ariaLabel={t('actions.menu', { name: memory.name })}
                    customActions={['Open', 'Delete']}
                    getActionErrorMessage={(actionError) =>
                      getApiErrorMessage(actionError, t('actions.restoreFailed'))
                    }
                    getActionSuccessMessage={() => t('actions.restored')}
                    modalContentByAction={{
                      'Bring back': {
                        description: t('actions.restoreDescription'),
                        primaryActionLabel: t('actions.restore'),
                        title: t('actions.restoreTitle', { name: memory.name }),
                      },
                    }}
                    onActionConfirm={() => handleRestore(memory)}
                    onCustomAction={(action) => {
                      if (action === 'Delete') {
                        setDeleting(memory);
                        return;
                      }

                      router.push(memoryPath(memory));
                    }}
                  />
                </div>
              </DashboardTableActionsCell>
            </tr>
          ))}
        </DashboardTableShell>
      </DashboardDataCard>

      <CreateMemoryModal
        isSubmitting={isCreateSubmitting}
        open={isCreating}
        providers={providers ?? []}
        onClose={() => setIsCreating(false)}
        onSubmit={submitCreate}
      />
      <MemoryDeleteModal memory={deleting} onClose={() => setDeleting(null)} />
    </>
  );
}
