'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { CreateSandboxModal } from '@/components/dashboard/workflows/sandboxes/create-sandbox-modal';
import { SandboxActionsMenu } from '@/components/dashboard/workflows/sandboxes/sandbox-actions-menu';
import { SandboxStatusBadge } from '@/components/dashboard/workflows/sandboxes/sandbox-badges';
import { useNotification } from '@/components/ui/notifications';
import { TableCellText } from '@/components/ui/table-cell';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  archiveSandbox,
  createSandbox,
  deriveErrorMessage,
  getApiErrorMessage,
  getSandboxes,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CreateSandboxFormInput } from '@/schemas/sandbox-schemas';
import type { Sandbox, SandboxSortField } from '@/types/sandbox';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

/** The tenant's sandboxes: code a workflow can run, each with its saved versions. */
export function SandboxesCard() {
  const t = useTranslations('dashboard.sandboxes.list');
  const tKind = useTranslations('dashboard.sandboxes.kind');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const [isCreating, setIsCreating] = useState(false);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<SandboxSortField>();
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getSandboxes(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['sandboxes', orgSlug, tenantSlug, after, rowsPerPage, sortDirection, sortField],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const columns: DashboardTableColumn<SandboxSortField>[] = [
    { className: 'w-[36%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[18%]', label: t('columns.runs') },
    { className: 'w-[14%]', label: t('columns.status') },
    { className: 'w-[12%]', label: t('columns.latest') },
    { className: 'w-[20%]', label: t('columns.updated'), sortField: 'updated_at' },
  ];

  const { isPending: isCreateSubmitting, mutate: submitCreate } = useMutation({
    mutationFn: ({ name, runs }: CreateSandboxFormInput) =>
      createSandbox(orgSlug ?? '', tenantSlug, {
        kind: runs === 'image' ? 'image' : 'code',
        language: runs === 'image' ? null : runs,
        name,
      }),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('createFailed')),
        type: 'error',
      });
    },
    onSuccess: async (sandbox) => {
      setIsCreating(false);
      showNotification({ message: t('created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['sandboxes', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      router.push(sandboxPath(sandbox));
    },
  });

  function sandboxPath(sandbox: Sandbox) {
    return getTenantScopedPath(
      isTenantView,
      orgSlug,
      tenantSlug,
      `sandboxes/${sandbox.id}`,
      `sandboxes/${sandbox.id}`,
    );
  }

  async function handleArchive(sandbox: Sandbox) {
    await archiveSandbox(orgSlug ?? '', tenantSlug, sandbox.id);
    await queryClient.invalidateQueries({ queryKey: ['sandboxes', orgSlug, tenantSlug] });
  }

  function kindLabel(sandbox: Sandbox) {
    if (sandbox.kind === 'image') {
      return tKind('image');
    }

    return sandbox.language === 'javascript' ? tKind('javascript') : tKind('python');
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={hasPermission('Workflows', 'Create') ? t('create') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            itemCount={data?.items.length ?? 0}
            nextCursor={data?.nextCursor ?? null}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="sandboxes-rows-per-page"
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        secondaryActionLabel={
          hasPermission('Workflows', 'ConnectAccounts') ? t('registries') : undefined
        }
        title={t('title')}
        onActionClick={() => setIsCreating(true)}
        onSecondaryActionClick={() =>
          router.push(
            getTenantScopedPath(
              isTenantView,
              orgSlug,
              tenantSlug,
              'sandboxes/registries',
              'sandboxes/registries',
            ),
          )
        }
      >
        <DashboardTableShell
          columns={columns}
          emptyMessage={t('empty')}
          hasActionsColumn
          isEmpty={(data?.items.length ?? 0) === 0}
          isLoading={isLoading}
          loadingMessage={t('loading')}
          minWidthClassName="min-w-190"
          onSortChange={handleSortChange}
          sortDirection={sortDirection}
          sortField={sortField}
        >
          {(data?.items ?? []).map((sandbox) => (
            <tr
              key={sandbox.id}
              className="group h-11 cursor-pointer transition hover:bg-hoverBg"
              onClick={() => router.push(sandboxPath(sandbox))}
            >
              <td className="px-4 py-2">
                <TableCellText className="font-semibold text-white">{sandbox.name}</TableCellText>
              </td>
              <td className="px-4 py-2">
                <TableCellText>{kindLabel(sandbox)}</TableCellText>
              </td>
              <td className="px-4 py-2">
                <SandboxStatusBadge status={sandbox.status} />
              </td>
              <td className="px-4 py-2">
                <TableCellText>
                  {sandbox.latestVersion > 0
                    ? t('versionNumber', { number: sandbox.latestVersion })
                    : t('noVersion')}
                </TableCellText>
              </td>
              <td className="px-4 py-2">
                <TableCellText>{formatBackendDateTime(sandbox.updatedAt)}</TableCellText>
              </td>
              <DashboardTableActionsCell className="px-4 py-2">
                <div className="flex justify-end">
                  <SandboxActionsMenu
                    canArchive={hasPermission('Workflows', 'Delete')}
                    sandbox={sandbox}
                    onAction={() => router.push(sandboxPath(sandbox))}
                    onArchive={() => handleArchive(sandbox)}
                  />
                </div>
              </DashboardTableActionsCell>
            </tr>
          ))}
        </DashboardTableShell>
      </DashboardDataCard>

      <CreateSandboxModal
        isSubmitting={isCreateSubmitting}
        open={isCreating}
        onClose={() => setIsCreating(false)}
        onSubmit={submitCreate}
      />
    </>
  );
}
