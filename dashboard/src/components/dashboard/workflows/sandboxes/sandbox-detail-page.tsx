'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { PushVersionModal } from '@/components/dashboard/workflows/sandboxes/push-version-modal';
import {
  BuildStatusBadge,
  SandboxStatusBadge,
} from '@/components/dashboard/workflows/sandboxes/sandbox-badges';
import { useSandboxRouteParams } from '@/components/dashboard/workflows/sandboxes/use-sandbox-route-params';
import { VersionDetails } from '@/components/dashboard/workflows/sandboxes/version-details';
import { VersionEditor } from '@/components/dashboard/workflows/sandboxes/version-editor';
import {
  seedFromVersion,
  type VersionSeed,
} from '@/components/dashboard/workflows/sandboxes/version-seed';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { TableCellText } from '@/components/ui/table-cell';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import { archiveSandbox, getApiErrorMessage, getSandbox } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Sandbox, SandboxVersion, WrittenSandboxCode } from '@/types/sandbox';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

function versionsBuilding(versions: SandboxVersion[]) {
  return versions.some((version) => version.build.status === 'building');
}

function languageWord(sandbox: Sandbox) {
  if (sandbox.kind === 'image') {
    return 'image' as const;
  }

  return sandbox.language === 'javascript' ? ('javascript' as const) : ('python' as const);
}

/** One sandbox: its versions, what each runs, and saving the next one. */
export default function SandboxDetailPage() {
  const t = useTranslations('dashboard.sandboxes.detail');
  const tKind = useTranslations('dashboard.sandboxes.kind');
  const tNav = useNavLabels();
  const { isTenantView, orgSlug, sandboxId, tenantSlug } = useSandboxRouteParams();
  const { hasPermission } = useTenantPermissions();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [seed, setSeed] = useState<VersionSeed | null>(null);
  const [isPushing, setIsPushing] = useState(false);
  const [isArchiving, setIsArchiving] = useState(false);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    resetToFirstPage,
    rowsPerPage,
  } = useTableQueryState<never>();
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && sandboxId),
    queryFn: () => getSandbox(orgSlug ?? '', tenantSlug, sandboxId, { after, limit: rowsPerPage }),
    queryKey: ['sandbox', orgSlug, tenantSlug, sandboxId, after, rowsPerPage],
    refetchInterval: (query) =>
      query.state.data && versionsBuilding(query.state.data.versions.items) ? 5_000 : false,
    retry: false,
  });
  const { isPending: isArchivePending, mutate: submitArchive } = useMutation({
    mutationFn: () => archiveSandbox(orgSlug ?? '', tenantSlug, sandboxId),
    onError: (mutationError) => {
      setIsArchiving(false);
      showNotification({
        message: getApiErrorMessage(mutationError, t('archiveFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsArchiving(false);
      showNotification({ message: t('archived'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['sandbox', orgSlug, tenantSlug] });
      await queryClient.invalidateQueries({ queryKey: ['sandboxes', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const sandbox = data?.sandbox ?? null;
  const versions = data?.versions.items ?? [];
  const selected = versions.find((version) => version.id === selectedId) ?? versions[0] ?? null;
  const canUpdate = hasPermission('Workflows', 'Update');
  const isActive = sandbox?.status === 'active';
  const sandboxesPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'sandboxes',
    'sandboxes',
  );
  const headerTrail = isTenantView
    ? [{ href: sandboxesPath, icon: 'terminal' }, { title: sandbox?.name ?? t('fallbackName') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview'),
          title: companyDisplayName,
        },
        { href: sandboxesPath, title: tNav.label('Sandboxes') },
        { title: sandbox?.name ?? t('fallbackName') },
      ];
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[16%]', label: t('columns.version') },
    { className: 'w-[34%]', label: t('columns.runtime') },
    { className: 'w-[20%]', label: t('columns.build') },
    { className: 'w-[30%]', label: t('columns.saved') },
  ];

  function openEditor(packagesToPin: string[] = []) {
    if (!sandbox) {
      return;
    }

    const base = seedFromVersion(sandbox, selected);

    setSeed({
      ...base,
      packages: [...base.packages, ...packagesToPin.map((name) => ({ name, version: '' }))],
    });
  }

  function openFixed(written: WrittenSandboxCode) {
    if (!sandbox) {
      return;
    }

    setSeed({
      ...seedFromVersion(sandbox, selected),
      code: written.code,
      explanation: written.explanation,
    });
  }

  function handleSaved(version: SandboxVersion) {
    setSeed(null);
    resetToFirstPage();
    setSelectedId(version.id);
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
          <div className="mx-auto flex w-full max-w-240 flex-col gap-4">
            {error ? (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
                {getApiErrorMessage(error, t('loadFailed'))}
              </p>
            ) : null}

            {isLoading ? <p className="text-sm text-textGray">{t('loading')}</p> : null}

            {sandbox ? (
              <>
                <section className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-borderGray bg-cardBg p-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-base font-bold text-white">{sandbox.name}</h1>
                      <SandboxStatusBadge status={sandbox.status} />
                    </div>
                    <p className="mt-1 text-xs text-textGray">
                      {tKind(languageWord(sandbox))}
                      {' · '}
                      {t('made', { at: formatBackendDateTime(sandbox.createdAt) })}
                    </p>
                  </div>
                  {seed === null ? (
                    <div className="flex flex-wrap gap-2">
                      {hasPermission('Workflows', 'Delete') && isActive ? (
                        <Button
                          className="w-auto"
                          type="button"
                          variant="outline"
                          onClick={() => setIsArchiving(true)}
                        >
                          {t('archive')}
                        </Button>
                      ) : null}
                      {canUpdate && isActive ? (
                        <Button className="w-auto" type="button" onClick={() => openEditor()}>
                          {t('newVersion')}
                        </Button>
                      ) : null}
                    </div>
                  ) : null}
                </section>

                {!isActive ? (
                  <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs text-textGray">
                    {t('archivedNote')}
                  </p>
                ) : null}

                {seed ? (
                  <VersionEditor
                    sandbox={sandbox}
                    seed={seed}
                    onCancel={() => setSeed(null)}
                    onSaved={handleSaved}
                  />
                ) : (
                  <>
                    <DashboardDataCard
                      className="max-w-none"
                      description={t('versionsDescription')}
                      footer={
                        <DashboardPagination
                          currentPage={currentPage}
                          itemCount={versions.length}
                          nextCursor={data?.versions.nextCursor ?? null}
                          rowsPerPage={rowsPerPage}
                          rowsPerPageSelectId="sandbox-versions-rows-per-page"
                          onNext={handleNextPage}
                          onPrevious={handlePreviousPage}
                          onRowsPerPageChange={handleRowsPerPageChange}
                        />
                      }
                      title={t('versions')}
                    >
                      <DashboardTableShell
                        columns={columns}
                        emptyMessage={t('noVersions')}
                        isEmpty={versions.length === 0}
                        isLoading={isLoading}
                        loadingMessage={t('loading')}
                        minWidthClassName="min-w-160"
                        onSortChange={() => {}}
                      >
                        {versions.map((version) => (
                          <tr
                            key={version.id}
                            className={`h-11 cursor-pointer transition hover:bg-hoverBg ${
                              version.id === selected?.id ? 'bg-primary/15' : ''
                            }`}
                            onClick={() => setSelectedId(version.id)}
                          >
                            <td className="px-4 py-2">
                              <TableCellText className="font-semibold text-white">
                                {t('versionNumber', { number: version.number })}
                              </TableCellText>
                            </td>
                            <td className="px-4 py-2">
                              <TableCellText>
                                {version.kind === 'image'
                                  ? version.image
                                  : (version.runtime ?? version.image)}
                              </TableCellText>
                            </td>
                            <td className="px-4 py-2">
                              <BuildStatusBadge status={version.build.status} />
                            </td>
                            <td className="px-4 py-2">
                              <TableCellText>
                                {formatBackendDateTime(version.createdAt)}
                              </TableCellText>
                            </td>
                          </tr>
                        ))}
                      </DashboardTableShell>
                    </DashboardDataCard>

                    {selected ? (
                      <VersionDetails
                        key={selected.id}
                        canUpdate={canUpdate}
                        sandbox={sandbox}
                        version={selected}
                        onFixed={openFixed}
                        onPin={openEditor}
                        onPush={() => setIsPushing(true)}
                      />
                    ) : null}
                  </>
                )}
              </>
            ) : null}
          </div>
        </main>
      </div>

      {isPushing && selected ? (
        <PushVersionModal
          sandboxId={sandboxId}
          version={selected}
          onClose={() => setIsPushing(false)}
        />
      ) : null}

      <ActionConfirmModal
        confirmationValue=""
        content={
          isArchiving
            ? {
                description: t('archiveDescription', { name: sandbox?.name ?? '' }),
                primaryActionLabel: t('archive'),
                secondaryActionLabel: t('dismiss'),
                title: t('archiveTitle', { name: sandbox?.name ?? '' }),
              }
            : null
        }
        isSubmitting={isArchivePending}
        onClose={() => setIsArchiving(false)}
        onConfirm={() => submitArchive()}
        onConfirmationChange={() => {}}
      />
    </div>
  );
}
