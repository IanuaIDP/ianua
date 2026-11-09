'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { AddDomainModal } from '@/components/dashboard/tenant-detail/sections/domains/add-domain-modal';
import { DomainsTable } from '@/components/dashboard/tenant-detail/sections/domains/domains-table';
import { TransferDomainModal } from '@/components/dashboard/tenant-detail/sections/domains/transfer-domain-modal';
import { useNotification } from '@/components/ui/notifications';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantDomain,
  deleteTenantDomain,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantDomains,
  provisionTenantDomainTls,
  transferTenantDomain,
  verifyTenantDomain,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { AddDomainInput } from '@/schemas/domain-schemas';
import type { Domain, DomainAction, DomainSortField } from '@/types/domain';
import {
  CERTIFICATE_POLL_INTERVAL_MS,
  getDnsInstructions,
  isAwaitingCertificate,
} from '@/utils/domain';

export function DomainsCard() {
  const t = useTranslations('dashboard.domains');
  const tInstructions = useLooseTranslations('dashboard.domains.instructions');
  const tErrors = useTranslations('common.errors');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateDomain = hasPermission('Domains', 'Create');
  const canDeleteDomain = hasPermission('Domains', 'Delete');
  const canUpdateDomain = hasPermission('Domains', 'Update');
  const canTransferDomain = canUpdateDomain && !isTenantView;
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
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
  } = useTableQueryState<DomainSortField>();
  const [isAddDomainModalOpen, setIsAddDomainModalOpen] = useState(false);
  const [instructionsModal, setInstructionsModal] = useState<{
    domain: Domain;
    isNewlyCreated: boolean;
  } | null>(null);
  const [transferDomain, setTransferDomain] = useState<Domain | null>(null);
  const instructions = instructionsModal
    ? getDnsInstructions(instructionsModal.domain, tInstructions)
    : null;

  const {
    data: domainsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantDomains(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['tenant-domains', orgSlug, tenantSlug, after, rowsPerPage, sortField, sortDirection],
    refetchInterval: (query) =>
      query.state.data?.items.some(isAwaitingCertificate) ? CERTIFICATE_POLL_INTERVAL_MS : false,
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { mutateAsync: submitDeleteDomain } = useMutation({
    mutationFn: (domainId: string) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteTenantDomain(orgSlug, tenantSlug, domainId);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { isPending: isAddingDomain, mutate: submitAddDomain } = useMutation({
    mutationFn: (payload: AddDomainInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantDomain(orgSlug, tenantSlug, payload);
    },
    onSuccess: async (domain) => {
      setIsAddDomainModalOpen(false);
      setInstructionsModal({ domain, isNewlyCreated: true });
      showNotification({ message: t('toasts.added'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.addFailed')),
        type: 'error',
      });
    },
  });

  const { mutateAsync: submitVerifyDomain } = useMutation({
    mutationFn: (domainId: string) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return verifyTenantDomain(orgSlug, tenantSlug, domainId);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { mutateAsync: submitProvisionTls } = useMutation({
    mutationFn: (domainId: string) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return provisionTenantDomainTls(orgSlug, tenantSlug, domainId);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { isPending: isTransferringDomain, mutate: submitTransferDomain } = useMutation({
    mutationFn: (targetTenantId: string) => {
      if (!orgSlug || !transferDomain) {
        throw new Error(tErrors('organizationMissing'));
      }

      return transferTenantDomain(orgSlug, tenantSlug, transferDomain.id, targetTenantId);
    },
    onSuccess: async () => {
      setTransferDomain(null);
      showNotification({ message: t('toasts.transferred'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains'] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.transferFailed')),
        type: 'error',
      });
    },
  });

  async function handleDomainAction(domain: Domain, action: DomainAction) {
    if (action === 'Delete') {
      await submitDeleteDomain(domain.id);
      return;
    }

    if (action === 'Verify') {
      await submitVerifyDomain(domain.id);
      return;
    }

    if (action === 'ProvisionTls') {
      await submitProvisionTls(domain.id);
    }
  }

  function handleViewInstructions(domain: Domain) {
    setInstructionsModal({ domain, isNewlyCreated: false });
  }

  function handleTransfer(domain: Domain) {
    setTransferDomain(domain);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('add')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="domains-rows-per-page"
            itemCount={domainsList?.items.length ?? 0}
            nextCursor={domainsList?.nextCursor ?? null}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        onActionClick={canCreateDomain ? () => setIsAddDomainModalOpen(true) : undefined}
      >
        <DomainsTable
          canDeleteDomain={canDeleteDomain}
          canTransferDomain={canTransferDomain}
          canUpdateDomain={canUpdateDomain}
          domains={domainsList?.items ?? []}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onDomainAction={handleDomainAction}
          onSortChange={handleSortChange}
          onTransfer={handleTransfer}
          onViewInstructions={handleViewInstructions}
        />
      </DashboardDataCard>

      <AddDomainModal
        isSubmitting={isAddingDomain}
        open={isAddDomainModalOpen}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setIsAddDomainModalOpen(false)}
        onSubmit={submitAddDomain}
      />
      <MemberCreatedModal
        open={Boolean(instructionsModal)}
        title={instructionsModal?.isNewlyCreated ? t('instructionsAdded') : t('instructionsTitle')}
        description={instructions?.description}
        fields={instructions?.fields}
        footer={
          instructions?.notes.length ? (
            <div className="flex flex-col gap-2">
              {instructions.notes.map((note) => (
                <p key={note} className="text-xs text-textGray">
                  {note}
                </p>
              ))}
            </div>
          ) : undefined
        }
        onClose={() => setInstructionsModal(null)}
      />
      <TransferDomainModal
        currentTenantSlug={tenantSlug}
        domain={transferDomain}
        isSubmitting={isTransferringDomain}
        open={Boolean(transferDomain)}
        orgSlug={orgSlug}
        onClose={() => setTransferDomain(null)}
        onSubmit={submitTransferDomain}
      />
    </>
  );
}
