'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTabs } from '@/components/dashboard/shared/dashboard-tabs';
import { StreamFormModal } from '@/components/dashboard/tenant-detail/sections/streams/stream-form-modal';
import { StreamsTable } from '@/components/dashboard/tenant-detail/sections/streams/streams-table';
import { useNotification } from '@/components/ui/notifications';
import { STREAM_STATUS_TABS } from '@/constants/stream';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  executeStreamAction,
  getApiErrorMessage,
  getTenantStreams,
  registerTenantStream,
  updateTenantStream,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { StreamFormInput } from '@/schemas/stream-schemas';
import type { Stream, StreamAction, StreamStatus } from '@/types/stream';
import { getStreamManagementPath, getStreamPath } from '@/utils/dashboard-routes';
import { toStreamFormValues } from '@/utils/stream';

export function StreamsCard() {
  const t = useTranslations('dashboard.streams');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateStream = hasPermission('Signals', 'Create');
  const canUpdateStream = hasPermission('Signals', 'Update');
  const canDeleteStream = hasPermission('Signals', 'Delete');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [activeTab, setActiveTab] = useState<'All' | StreamStatus>('All');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createdReceiverKey, setCreatedReceiverKey] = useState<string | null>(null);
  const [editingStream, setEditingStream] = useState<Stream | null>(null);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    resetToFirstPage,
    rowsPerPage,
  } = useTableQueryState<never>();
  const status = activeTab === 'All' ? undefined : activeTab;

  const {
    data: streamsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantStreams(orgSlug ?? '', tenantSlug, { after, limit: rowsPerPage, status }),
    queryKey: ['tenant-streams', orgSlug, tenantSlug, status, after, rowsPerPage],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateStreams() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-streams', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isCreatingStream, mutate: submitCreateStream } = useMutation({
    mutationFn: (payload: StreamFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return registerTenantStream(orgSlug, tenantSlug, payload);
    },
    onSuccess: async (receiverKey) => {
      setIsCreateModalOpen(false);
      setCreatedReceiverKey(receiverKey);
      showNotification({ message: t('toasts.registered'), type: 'success' });
      await invalidateStreams();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.registerFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdatingStream, mutate: submitUpdateStream } = useMutation({
    mutationFn: (payload: StreamFormInput) => {
      if (!orgSlug || !editingStream) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantStream(orgSlug, tenantSlug, editingStream.id, payload);
    },
    onSuccess: async () => {
      setEditingStream(null);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateStreams();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  async function handleStreamAction(stream: Stream, action: StreamAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeStreamAction(orgSlug, tenantSlug, stream, action);
    await invalidateStreams();
  }

  function handleStreamClick(stream: Stream) {
    if (!isTenantView) {
      router.push(getStreamManagementPath(tenantSlug, stream.id));
      return;
    }

    if (!orgSlug) {
      return;
    }

    router.push(getStreamPath(orgSlug, tenantSlug, stream.id));
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('register')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="tenant-streams-rows-per-page"
            itemCount={streamsList?.items.length ?? 0}
            nextCursor={streamsList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        tabs={
          <DashboardTabs
            activeTab={activeTab}
            tabs={STREAM_STATUS_TABS}
            onTabChange={(tab) => {
              setActiveTab(tab);
              resetToFirstPage();
            }}
          />
        }
        onActionClick={canCreateStream ? () => setIsCreateModalOpen(true) : undefined}
      >
        <StreamsTable
          canDeleteStream={canDeleteStream}
          canUpdateStream={canUpdateStream}
          isLoading={isLoading}
          streams={streamsList?.items ?? []}
          onEditClick={setEditingStream}
          onRowClick={handleStreamClick}
          onStreamAction={handleStreamAction}
        />
      </DashboardDataCard>

      <StreamFormModal
        open={isCreateModalOpen}
        title={t('registerModal.title')}
        description={t('registerModal.description')}
        primaryActionLabel={t('registerModal.submit')}
        isSubmitting={isCreatingStream}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreateStream}
      />
      <StreamFormModal
        open={Boolean(editingStream)}
        title={t('editModal.title')}
        description={t('editModal.description')}
        primaryActionLabel={t('editModal.submit')}
        defaultValues={editingStream ? toStreamFormValues(editingStream) : undefined}
        isSubmitting={isUpdatingStream}
        onClose={() => setEditingStream(null)}
        onSubmit={submitUpdateStream}
      />

      <MemberCreatedModal
        description={t('receiverKeyDescription')}
        fields={createdReceiverKey ? [{ label: t('receiverKey'), value: createdReceiverKey }] : []}
        open={Boolean(createdReceiverKey)}
        title={t('receiverKeyTitle')}
        onClose={() => setCreatedReceiverKey(null)}
      />
    </>
  );
}
