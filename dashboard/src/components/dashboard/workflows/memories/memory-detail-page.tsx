'use client';

import { useState } from 'react';
import { useParams } from 'next/navigation';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { MemoryDeleteModal } from '@/components/dashboard/workflows/memories/memory-delete-modal';
import { hasLostItsModel } from '@/components/dashboard/workflows/memories/memory-status';
import { MemoryTexts } from '@/components/dashboard/workflows/memories/memory-texts';
import { ExposureBadge, ToneBadge } from '@/components/dashboard/workflows/workflow-badges';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import { getApiErrorMessage, getMemories, getTenantModelProviders, restoreMemory } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

/** One memory: what fills it, how sensitive it may be, and its texts for those who may read them. */
export default function MemoryDetailPage() {
  const t = useTranslations('dashboard.memories.detail');
  const tNav = useNavLabels();
  const params = useParams<{ memoryId: string }>();
  const memoryId = decodeURIComponent(params.memoryId);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const [isDeleting, setIsDeleting] = useState(false);
  const hasOrg = Boolean(orgSlug && tenantSlug);
  const {
    data: memories,
    error,
    isLoading,
  } = useQuery({
    enabled: hasOrg,
    queryFn: () => getMemories(orgSlug ?? '', tenantSlug),
    queryKey: ['memories', orgSlug, tenantSlug],
    retry: false,
  });
  const { data: providers } = useQuery({
    enabled: hasOrg,
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
    retry: false,
  });
  const memory = memories?.find((candidate) => candidate.id === memoryId) ?? null;
  const canDelete = hasPermission('Workflows', 'Delete');
  const { isPending: isRestoring, mutate: submitRestore } = useMutation({
    mutationFn: () => restoreMemory(orgSlug ?? '', tenantSlug, memoryId),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('restoreFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('restored'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['memories', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });
  const memoriesPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'memories',
    'memories',
  );
  const headerTrail = isTenantView
    ? [{ href: memoriesPath, icon: 'psychology' }, { title: memory?.name ?? t('fallbackName') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview'),
          title: companyDisplayName,
        },
        { href: memoriesPath, title: tNav.label('Memories') },
        { title: memory?.name ?? t('fallbackName') },
      ];

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Memories"
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

            {!isLoading && !error && !memory ? (
              <p className="text-sm text-textGray">{t('notFound')}</p>
            ) : null}

            {memory ? (
              <>
                <section className="rounded-lg border border-borderGray bg-cardBg p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-base font-bold text-white">{memory.name}</h1>
                      <ExposureBadge exposure={memory.clearance} />
                    </div>
                    {canDelete ? (
                      <div>
                        {memory.status === 'deletion_requested' ? (
                          <Button
                            disabled={isRestoring}
                            isLoading={isRestoring}
                            type="button"
                            onClick={() => submitRestore()}
                          >
                            {t('restore')}
                          </Button>
                        ) : (
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => setIsDeleting(true)}
                          >
                            {t('delete')}
                          </Button>
                        )}
                      </div>
                    ) : null}
                  </div>

                  {memory.status === 'deletion_requested' ? (
                    <p className="mt-3 rounded-lg bg-error/10 px-3 py-2 text-xs text-error">
                      {t('deleting', { at: formatBackendDateTime(memory.deletedAfter ?? '') })}
                    </p>
                  ) : null}

                  {hasLostItsModel(memory, providers) ? (
                    <div className="mt-3">
                      <ToneBadge tone="warn">{t('modelGone')}</ToneBadge>
                      <p className="mt-1 text-xs text-textGray">{t('modelGoneHint')}</p>
                    </div>
                  ) : null}

                  <dl className="mt-4 grid grid-cols-1 gap-3 text-xs sm:grid-cols-3">
                    <div>
                      <dt className="text-textGray">{t('filledBy')}</dt>
                      <dd className="text-white">
                        {memory.embeddingSource === 'platform' ? t('platform') : t('provider')}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-textGray">{t('model')}</dt>
                      <dd className="break-all text-white">{memory.embeddingModel}</dd>
                    </div>
                    <div>
                      <dt className="text-textGray">{t('made')}</dt>
                      <dd className="text-white">{formatBackendDateTime(memory.createdAt)}</dd>
                    </div>
                  </dl>
                </section>

                {canDelete ? <MemoryTexts memoryId={memory.id} /> : null}
              </>
            ) : null}
          </div>
        </main>
      </div>

      <MemoryDeleteModal memory={isDeleting ? memory : null} onClose={() => setIsDeleting(false)} />
    </div>
  );
}
