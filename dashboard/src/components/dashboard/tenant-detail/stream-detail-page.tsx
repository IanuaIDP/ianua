'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { StreamDeliveriesTable } from '@/components/dashboard/tenant-detail/sections/streams/stream-deliveries-table';
import { StreamFormModal } from '@/components/dashboard/tenant-detail/sections/streams/stream-form-modal';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { useNotification } from '@/components/ui/notifications';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { useStreamActionModalContent } from '@/hooks/dashboard/use-stream-action-modal-content';
import { useStreamOptions } from '@/hooks/dashboard/use-stream-options';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useStreamRouteParams } from '@/hooks/tenants/use-stream-route-params';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  deriveErrorMessage,
  executeStreamAction,
  getApiErrorMessage,
  getStreamDeliveries,
  getTenantStream,
  updateTenantStream,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { StreamFormInput } from '@/schemas/stream-schemas';
import type { Stream, StreamAction } from '@/types/stream';
import { cn } from '@/utils/cn';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { toStreamFormValues } from '@/utils/stream';
import { useAppStore } from '@/store/app-store';

export default function StreamDetailPage() {
  const t = useTranslations('dashboard.streams');
  const tDetail = useTranslations('dashboard.streams.detail');
  const tActions = useTranslations('dashboard.actions.labels');
  const tErrors = useTranslations('common.errors');
  const streamActionModalContent = useStreamActionModalContent();
  const { deliveryMethodLabel, signalTypeLabel } = useStreamOptions();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const copy = useCopyToClipboard();
  const isSidebarOpen = useAppStore((state) => state.isSidebarOpen);
  const { isTenantView, orgSlug, streamId, tenantSlug } = useStreamRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateStream = hasPermission('Signals', 'Update');
  const canDeleteStream = hasPermission('Signals', 'Delete');

  const [isEditOpen, setIsEditOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<StreamAction | null>(null);
  const [confirmationValue, setConfirmationValue] = useState('');

  const streamsPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'streams', 'streams');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const {
    data: stream,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && streamId),
    queryFn: () => getTenantStream(orgSlug ?? '', tenantSlug, streamId),
    queryKey: ['tenant-stream', orgSlug, tenantSlug, streamId],
  });

  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    rowsPerPage,
  } = useTableQueryState<never>({ initialRowsPerPage: 50 });

  const {
    data: deliveriesList,
    error: deliveriesError,
    isLoading: isLoadingDeliveries,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && streamId),
    queryFn: () =>
      getStreamDeliveries(orgSlug ?? '', tenantSlug, streamId, { after, limit: rowsPerPage }),
    queryKey: ['stream-deliveries', orgSlug, tenantSlug, streamId, after, rowsPerPage],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, tDetail('loadFailed'))],
  );

  const deliveriesErrorMessage = deriveErrorMessage([
    deliveriesError,
    getApiErrorMessage(deliveriesError, tDetail('deliveriesLoadFailed')),
  ]);

  async function invalidateStream() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-stream', orgSlug, tenantSlug, streamId],
    });
    await queryClient.invalidateQueries({ queryKey: ['tenant-streams', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function handleStreamAction(target: Stream, action: StreamAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeStreamAction(orgSlug, tenantSlug, target, action);

    if (action === 'Delete') {
      router.push(streamsPath);
      return;
    }

    await invalidateStream();
  }

  const { isPending: isUpdatingStream, mutate: submitUpdateStream } = useMutation({
    mutationFn: (payload: StreamFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantStream(orgSlug, tenantSlug, streamId, payload);
    },
    onSuccess: async () => {
      setIsEditOpen(false);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateStream();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isSubmittingAction, mutate: submitPendingAction } = useMutation({
    mutationFn: () => {
      if (!stream || !pendingAction) {
        throw new Error('Nothing to confirm.');
      }

      return handleStreamAction(stream, pendingAction);
    },
    onSuccess: () => {
      const action = pendingAction;
      setPendingAction(null);
      setConfirmationValue('');
      showNotification({
        message: action && action !== 'Edit' ? t(`actionSuccess.${action}`) : tDetail('actionDone'),
        type: 'success',
      });
    },
    onError: (mutationError) => {
      setPendingAction(null);
      setConfirmationValue('');
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const headerTrail = isTenantView
    ? [{ href: streamsPath, icon: 'sensors' }, { title: tDetail('title') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: streamsPath, title: t('title') },
        { title: tDetail('title') },
      ];

  const visibleSignalTypes = stream ? stream.signalTypes.slice(0, isSidebarOpen ? 1 : 2) : [];
  const hiddenSignalTypesCount = stream ? stream.signalTypes.length - visibleSignalTypes.length : 0;
  const primaryAction: StreamAction | null =
    stream?.status === 'Active' ? 'Pause' : stream?.status === 'Paused' ? 'Resume' : null;

  async function copyEndpoint(endpoint: string) {
    await copy(endpoint, t('endpointCopied'));
  }

  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Signals"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          {errorMessage ? (
            <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
              {errorMessage}
            </p>
          ) : null}

          {isLoading ? (
            <p className="text-sm text-textGray">{tDetail('loading')}</p>
          ) : stream ? (
            <div className="flex flex-col gap-4">
              <div className="mx-auto w-full max-w-360 rounded-lg border border-borderGray bg-cardBg p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex flex-col gap-1">
                    <h1 className="truncate text-base font-bold text-white">{tDetail('title')}</h1>
                    <div className="flex min-w-0 items-center gap-1.5">
                      <span className="font-medium text-textGray text-xs">{stream.endpoint}</span>
                      <button
                        type="button"
                        aria-label={t('copyEndpoint')}
                        onClick={(event) => {
                          event.stopPropagation();
                          void copyEndpoint(stream.endpoint);
                        }}
                        className="flex size-5 shrink-0 items-center justify-center rounded text-textGray transition hover:text-white"
                      >
                        <span className="material-symbols-rounded text-base!" aria-hidden>
                          content_copy
                        </span>
                      </button>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {stream.status === 'Disabled' ? (
                      canDeleteStream ? (
                        <button
                          type="button"
                          onClick={() => setPendingAction('Delete')}
                          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-borderGray bg-transparent px-3.5 text-sm font-medium text-white transition hover:bg-hoverBg"
                        >
                          <span className="material-symbols-rounded text-base!" aria-hidden>
                            delete
                          </span>
                          {tActions('Delete')}
                        </button>
                      ) : null
                    ) : (
                      <>
                        {canUpdateStream ? (
                          <button
                            type="button"
                            onClick={() => setIsEditOpen(true)}
                            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-borderGray bg-transparent px-3.5 text-sm font-medium text-white transition hover:bg-hoverBg"
                          >
                            <span className="material-symbols-rounded text-base!" aria-hidden>
                              edit
                            </span>
                            {tActions('Edit')}
                          </button>
                        ) : null}
                        {canUpdateStream && primaryAction ? (
                          <button
                            type="button"
                            onClick={() => setPendingAction(primaryAction)}
                            className={cn(
                              'inline-flex h-8 items-center gap-1.5 rounded-lg px-3.5 text-sm font-medium transition',
                              primaryAction === 'Resume'
                                ? 'bg-focus text-white hover:bg-focus/90'
                                : 'border border-borderGray bg-transparent text-white hover:bg-hoverBg',
                            )}
                          >
                            <span className="material-symbols-rounded text-base!" aria-hidden>
                              {primaryAction === 'Pause' ? 'pause_circle' : 'play_circle'}
                            </span>
                            {tActions(primaryAction)}
                          </button>
                        ) : null}
                        {canUpdateStream ? (
                          <button
                            type="button"
                            onClick={() => setPendingAction('Disable')}
                            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-error bg-transparent px-3.5 text-sm font-medium text-error transition hover:bg-error/10"
                          >
                            <span className="material-symbols-rounded text-base!" aria-hidden>
                              cancel
                            </span>
                            {tActions('Disable')}
                          </button>
                        ) : null}
                      </>
                    )}
                  </div>
                </div>

                <div className="mt-3 grid grid-cols-1 overflow-hidden rounded-[10px] border border-borderGray sm:grid-cols-2 lg:grid-cols-4">
                  <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-r lg:border-b-0">
                    <span className="text-[10px] text-textGray">{tDetail('status')}</span>
                    <DashboardStatusBadge status={stream.status} />
                  </div>
                  <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 lg:border-b-0 lg:border-r">
                    <span className="text-[10px] text-textGray">{t('columns.deliveryMethod')}</span>
                    <span className="inline-flex h-5 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white">
                      {deliveryMethodLabel(stream.deliveryMethod)}
                    </span>
                  </div>
                  <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                    <span className="text-[10px] text-textGray">{t('columns.signalTypes')}</span>
                    <div className="flex flex-nowrap items-center gap-1 overflow-hidden">
                      {stream.signalTypes.length === 0 ? (
                        <span className="inline-flex items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white">
                          {t('allTypes')}
                        </span>
                      ) : (
                        <>
                          {visibleSignalTypes.map((signalType) => (
                            <span
                              key={signalType}
                              className="inline-flex shrink-0 items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white"
                            >
                              {signalTypeLabel(signalType)}
                            </span>
                          ))}
                          {hiddenSignalTypesCount > 0 ? (
                            <FloatingTooltip
                              title={t('columns.signalTypes')}
                              content={
                                <div className="flex max-w-64 flex-wrap gap-1">
                                  {stream.signalTypes.map((signalType) => (
                                    <span
                                      key={signalType}
                                      className="inline-flex h-5 items-center rounded-md bg-surfaceChip px-1.5 text-[10px] font-medium leading-none text-white"
                                    >
                                      {signalTypeLabel(signalType)}
                                    </span>
                                  ))}
                                </div>
                              }
                            >
                              <span className="inline-flex shrink-0 items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white hover:bg-white/15">
                                +{hiddenSignalTypesCount}
                              </span>
                            </FloatingTooltip>
                          ) : null}
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-start justify-center gap-1.5 px-4 py-3">
                    <span className="text-[10px] text-textGray">{t('columns.created')}</span>
                    <span className="text-xs text-white">{stream.created}</span>
                  </div>
                </div>
              </div>

              <DashboardDataCard
                description={tDetail('deliveriesDescription')}
                errorMessage={deliveriesErrorMessage}
                title={tDetail('deliveriesTitle')}
                footer={
                  <DashboardPagination
                    currentPage={currentPage}
                    rowsPerPage={rowsPerPage}
                    rowsPerPageSelectId="stream-deliveries-rows-per-page"
                    itemCount={deliveriesList?.items.length ?? 0}
                    nextCursor={deliveriesList?.nextCursor ?? null}
                    onNext={handleNextPage}
                    onPrevious={handlePreviousPage}
                    onRowsPerPageChange={handleRowsPerPageChange}
                  />
                }
              >
                <StreamDeliveriesTable
                  deliveries={deliveriesList?.items ?? []}
                  isLoading={isLoadingDeliveries}
                />
              </DashboardDataCard>
            </div>
          ) : null}
        </main>
      </div>

      <StreamFormModal
        open={isEditOpen}
        title={t('editModal.title')}
        description={t('editModal.description')}
        primaryActionLabel={t('editModal.submit')}
        defaultValues={stream ? toStreamFormValues(stream) : undefined}
        isSubmitting={isUpdatingStream}
        onClose={() => setIsEditOpen(false)}
        onSubmit={submitUpdateStream}
      />

      <ActionConfirmModal
        confirmationValue={confirmationValue}
        content={pendingAction ? streamActionModalContent[pendingAction] : null}
        isSubmitting={isSubmittingAction}
        onClose={() => {
          setPendingAction(null);
          setConfirmationValue('');
        }}
        onConfirm={() => submitPendingAction()}
        onConfirmationChange={setConfirmationValue}
      />
    </div>
  );
}
