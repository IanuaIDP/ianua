'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { DnsRecordsCard } from '@/components/dashboard/tenant-detail/sections/domains/dns-records-card';
import { DomainActionsMenu } from '@/components/dashboard/tenant-detail/sections/domains/domain-actions-menu';
import { TransferDomainModal } from '@/components/dashboard/tenant-detail/sections/domains/transfer-domain-modal';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { useNotification } from '@/components/ui/notifications';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useDomainRouteParams } from '@/hooks/tenants/use-domain-route-params';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  deleteTenantDomain,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantDomain,
  provisionTenantDomainTls,
  transferTenantDomain,
  verifyTenantDomain,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Domain, DomainAction } from '@/types/domain';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import {
  CERTIFICATE_POLL_INTERVAL_MS,
  getDnsInstructions,
  isAwaitingCertificate,
} from '@/utils/domain';

function isWildcardDomain(domain: string) {
  return domain.startsWith('*.');
}

export default function DomainDetailPage() {
  const t = useTranslations('dashboard.domains.detail');
  const tDomains = useTranslations('dashboard.domains');
  const tInstructions = useLooseTranslations('dashboard.domains.instructions');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { domainId, isTenantView, orgSlug, tenantSlug } = useDomainRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateDomain = hasPermission('Domains', 'Update');
  const canDeleteDomain = hasPermission('Domains', 'Delete');
  const canTransferDomain = canUpdateDomain && !isTenantView;

  const [instructionsModal, setInstructionsModal] = useState<{
    domain: Domain;
    isNewlyCreated: boolean;
  } | null>(null);
  const [isTransferOpen, setIsTransferOpen] = useState(false);

  const domainsPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'domains', 'domains');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const {
    data: domain,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && domainId),
    queryFn: () => getTenantDomain(orgSlug ?? '', tenantSlug, domainId),
    queryKey: ['tenant-domain-detail', orgSlug, tenantSlug, domainId],
    refetchInterval: (query) =>
      isAwaitingCertificate(query.state.data) ? CERTIFICATE_POLL_INTERVAL_MS : false,
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const instructions = instructionsModal
    ? getDnsInstructions(instructionsModal.domain, tInstructions)
    : null;

  async function invalidateDomain() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-domain-detail', orgSlug, tenantSlug, domainId],
    });
    await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { mutateAsync: submitDeleteDomain } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteTenantDomain(orgSlug, tenantSlug, domainId);
    },
    onSuccess: async () => {
      router.push(domainsPath);
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { mutateAsync: submitVerifyDomain } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return verifyTenantDomain(orgSlug, tenantSlug, domainId);
    },
    onSuccess: invalidateDomain,
  });

  const { mutateAsync: submitProvisionTls } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return provisionTenantDomainTls(orgSlug, tenantSlug, domainId);
    },
    onSuccess: invalidateDomain,
  });

  const { isPending: isTransferringDomain, mutate: submitTransferDomain } = useMutation({
    mutationFn: (targetTenantId: string) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return transferTenantDomain(orgSlug, tenantSlug, domainId, targetTenantId);
    },
    onSuccess: async () => {
      setIsTransferOpen(false);
      showNotification({ message: tDomains('toasts.transferred'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-domains'] });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-domain-detail', orgSlug, tenantSlug, domainId],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      router.push(domainsPath);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, tDomains('toasts.transferFailed')),
        type: 'error',
      });
    },
  });

  async function handleDomainAction(target: Domain, action: DomainAction) {
    if (action === 'Delete') {
      await submitDeleteDomain();
      return;
    }

    if (action === 'Verify') {
      await submitVerifyDomain();
      return;
    }

    if (action === 'ProvisionTls') {
      await submitProvisionTls();
    }
  }

  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);

  const headerTrail = isTenantView
    ? [{ href: domainsPath, icon: 'language' }, { title: domain?.domain ?? t('fallbackTitle') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: domainsPath, title: navLabels.label('Domains') },
        { title: domain?.domain ?? t('fallbackTitle') },
      ];

  const isDelegated = domain?.connection === 'Delegated';
  const isWildcard = domain ? isWildcardDomain(domain.domain) : false;

  const domainContent = domain ? (
    <div className="mx-auto flex w-full max-w-360 flex-col gap-4">
      <div className="rounded-lg border border-borderGray bg-cardBg p-4">
        <div className="flex items-center justify-between gap-3">
          <h1 className="truncate text-base font-bold text-white">{domain.domain}</h1>
          <DomainActionsMenu
            canDelete={canDeleteDomain}
            canTransfer={canTransferDomain}
            canUpdate={canUpdateDomain}
            domain={domain}
            onActionConfirm={handleDomainAction}
            onTransfer={() => setIsTransferOpen(true)}
            onViewInstructions={(target) =>
              setInstructionsModal({ domain: target, isNewlyCreated: false })
            }
          />
        </div>

        <div className="mt-3 grid grid-cols-1 overflow-hidden rounded-[10px] border border-borderGray sm:grid-cols-2 lg:grid-cols-4">
          <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-r lg:border-b-0">
            <span className="text-[10px] text-textGray">{t('verification')}</span>
            <DashboardStatusBadge status={domain.verificationStatus} />
          </div>
          <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 lg:border-b-0 lg:border-r">
            <span className="text-[10px] text-textGray">{t('tls')}</span>
            <DashboardStatusBadge status={domain.tlsStatus} />
          </div>
          <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
            <span className="text-[10px] text-textGray">{t('connection')}</span>
            <span className="text-xs text-white">
              {domain.connection === 'Delegated' ? t('delegatedLabel') : t('selfManagedLabel')}
            </span>
          </div>
          <div className="flex flex-col items-start justify-center gap-1.5 px-4 py-3">
            <span className="text-[10px] text-textGray">{t('created')}</span>
            <span className="text-xs text-white">{domain.created}</span>
          </div>
        </div>
      </div>

      {isDelegated && isWildcard ? (
        <div className="rounded-lg border border-borderGray bg-cardBg p-4 text-xs text-textGray">
          {t('wildcardNote')}
        </div>
      ) : isDelegated && domain.verificationStatus !== 'Verified' ? (
        <div className="rounded-lg border border-borderGray bg-cardBg p-4 text-xs text-textGray">
          {t('verifyFirst')}
        </div>
      ) : isDelegated ? (
        <DnsRecordsCard
          canUpdate={canUpdateDomain}
          domainId={domainId}
          orgSlug={orgSlug}
          tenantSlug={tenantSlug}
          zoneHostname={domain.domain}
        />
      ) : (
        <div className="rounded-lg border border-borderGray bg-cardBg p-4 text-xs text-textGray">
          {t('selfManagedNote')}
        </div>
      )}
    </div>
  ) : null;

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Domains"
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
            <p className="text-sm text-textGray">{t('loading')}</p>
          ) : domain ? (
            domainContent
          ) : (
            <p className="text-sm text-textGray">{t('notFound')}</p>
          )}
        </main>
      </div>

      <MemberCreatedModal
        open={Boolean(instructionsModal)}
        title={
          instructionsModal?.isNewlyCreated
            ? tDomains('instructionsAdded')
            : tDomains('instructionsTitle')
        }
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
        domain={isTransferOpen ? (domain ?? null) : null}
        isSubmitting={isTransferringDomain}
        open={isTransferOpen}
        orgSlug={orgSlug}
        onClose={() => setIsTransferOpen(false)}
        onSubmit={submitTransferDomain}
      />
    </div>
  );
}
