'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DnsRecordFormModal } from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-modal';
import { DnsRecordsTable } from '@/components/dashboard/tenant-detail/sections/domains/dns-records-table';
import { useNotification } from '@/components/ui/notifications';
import {
  deleteTenantDomainDnsRecord,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantDomainDnsRecords,
  putTenantDomainDnsRecord,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { DnsRecord, DnsRecordSetInput } from '@/types/dns-record';

type DnsRecordsCardProps = {
  canUpdate?: boolean;
  domainId: string;
  orgSlug?: string;
  tenantSlug: string;
  zoneHostname?: string;
};

export function DnsRecordsCard({
  canUpdate = true,
  domainId,
  orgSlug,
  tenantSlug,
  zoneHostname,
}: DnsRecordsCardProps) {
  const t = useTranslations('dashboard.domains.dns');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [formTarget, setFormTarget] = useState<DnsRecord | null | undefined>(undefined);
  const [deleteTarget, setDeleteTarget] = useState<DnsRecord | null>(null);

  const {
    data: records,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && domainId),
    queryFn: () => getTenantDomainDnsRecords(orgSlug ?? '', tenantSlug, domainId),
    queryKey: ['tenant-domain-dns-records', orgSlug, tenantSlug, domainId],
  });

  const errorMessage = deriveErrorMessage([error, getApiErrorMessage(error, t('loadFailed'))]);

  async function invalidateRecords() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-domain-dns-records', orgSlug, tenantSlug, domainId],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isSavingRecord, mutate: submitRecord } = useMutation({
    mutationFn: (payload: DnsRecordSetInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return putTenantDomainDnsRecord(orgSlug, tenantSlug, domainId, payload);
    },
    onSuccess: async () => {
      const wasEditing = Boolean(formTarget);
      setFormTarget(undefined);
      showNotification({
        message: wasEditing ? t('toasts.updated') : t('toasts.added'),
        type: 'success',
      });
      await invalidateRecords();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.saveFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isDeletingRecord, mutate: submitDelete } = useMutation({
    mutationFn: () => {
      if (!orgSlug || !deleteTarget) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteTenantDomainDnsRecord(orgSlug, tenantSlug, domainId, {
        name: deleteTarget.name,
        recordType: deleteTarget.recordType,
      });
    },
    onSuccess: async () => {
      setDeleteTarget(null);
      showNotification({ message: t('toasts.deleted'), type: 'success' });
      await invalidateRecords();
    },
    onError: (mutationError) => {
      setDeleteTarget(null);
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.deleteFailed')),
        type: 'error',
      });
    },
  });

  const deleteModalContent: DashboardActionModalContent | null = deleteTarget
    ? {
        description: t('deleteModal.description', {
          name: deleteTarget.name,
          type: deleteTarget.recordType,
        }),
        primaryActionLabel: t('deleteModal.submit'),
        title: t('deleteModal.title'),
        warningTone: 'danger',
      }
    : null;

  return (
    <>
      <DashboardDataCard
        actionLabel={canUpdate ? t('add') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={canUpdate ? () => setFormTarget(null) : undefined}
      >
        <DnsRecordsTable
          canUpdate={canUpdate}
          isLoading={isLoading}
          records={records ?? []}
          onDelete={setDeleteTarget}
          onEdit={setFormTarget}
        />
      </DashboardDataCard>

      <DnsRecordFormModal
        isSubmitting={isSavingRecord}
        record={formTarget}
        zoneHostname={zoneHostname}
        onClose={() => setFormTarget(undefined)}
        onSubmit={(payload) => submitRecord(payload)}
      />

      <ActionConfirmModal
        confirmationValue=""
        content={deleteModalContent}
        isSubmitting={isDeletingRecord}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => submitDelete()}
        onConfirmationChange={() => {}}
      />
    </>
  );
}
