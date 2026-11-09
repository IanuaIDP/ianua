'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import {
  AccessGrantedModal,
  type GrantedAccess,
} from '@/components/dashboard/tenant-detail/sections/agents/delegations/access-granted-modal';
import { CheckAuthorizationModal } from '@/components/dashboard/tenant-detail/sections/agents/delegations/check-authorization-modal';
import { DelegationsTable } from '@/components/dashboard/tenant-detail/sections/agents/delegations/delegations-table';
import { GrantDelegationModal } from '@/components/dashboard/tenant-detail/sections/agents/delegations/grant-delegation-modal';
import { useNotification } from '@/components/ui/notifications';
import {
  buildAuthorizationCapabilityOptions,
  buildDelegationCapabilityOptions,
  buildToolCapabilityOptions,
} from '@/constants/delegation';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';
import {
  deriveErrorMessage,
  getAgentApprovals,
  getAgentDelegations,
  getApiErrorMessage,
  getTenantAgent,
  getTenantCryptoKeys,
  getTenantDomains,
  getTenantServices,
  getTenantTools,
  grantAgentDelegation,
  grantDelegationResource,
  revokeAgentDelegation,
  revokeDelegationResource,
  rotateTenantCryptoKey,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { GrantDelegationInput, GrantResourceAccessInput } from '@/schemas/delegation-schemas';
import type { Delegation, DelegationAction } from '@/types/delegation';

export function DelegationsSection() {
  const t = useTranslations('dashboard.delegations');
  const tErrors = useTranslations('common.errors');
  const { permissionLabel } = useDelegationText();
  const { agentId, orgSlug, tenantSlug } = useAgentRouteParams();
  const { isTenantView } = useTenantRouteParams();
  const approvalsPath = `${
    isTenantView && orgSlug
      ? getAgentPath(orgSlug, tenantSlug, agentId)
      : getAgentManagementPath(tenantSlug, agentId)
  }/approvals`;
  const { hasPermission, permissionSet } = useTenantPermissions();
  const canManageDelegations = hasPermission('Agents', 'Delegate');
  const canCheckAuthorization = hasPermission('Agents', 'View');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isGrantModalOpen, setIsGrantModalOpen] = useState(false);
  const [isCheckAuthorizationOpen, setIsCheckAuthorizationOpen] = useState(false);
  const [grantedAccess, setGrantedAccess] = useState<GrantedAccess | null>(null);
  // Only while the dialog is open, and only for someone who could act on the
  // answer. A prerequisite hint is not worth an extra authenticated request on
  // every page load — and a 401 from one logs the whole session out.
  const { data: cryptoKeys, isError: cryptoKeysUnavailable } = useQuery({
    enabled: isGrantModalOpen && canManageDelegations && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantCryptoKeys(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
    retry: false,
  });

  // Unknown counts as present: this is a hint, and a hint that cannot be
  // checked must never be the thing standing between someone and a grant the
  // backend would have accepted.
  const hasSigningKey =
    cryptoKeysUnavailable || !cryptoKeys ? true : cryptoKeys.some((key) => key.status === 'Active');

  const { isPending: isPreparingSigningKey, mutate: prepareSigningKey } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return rotateTenantCryptoKey(orgSlug, tenantSlug, { algorithm: 'ES256' });
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.signingKeyFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.signingKeyCreated'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
      });
    },
  });

  // Only the domains that actually answer: an unverified one has no
  // certificate, so a request to it fails for a reason that has nothing to do
  // with the grant being tested.
  const { data: domains } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantDomains(orgSlug ?? '', tenantSlug, { limit: 50 }),
    queryKey: ['tenant-domains', orgSlug, tenantSlug, 'gateway-hosts'],
  });
  const gatewayHosts = (domains?.items ?? [])
    .filter((entry) => entry.verificationStatus === 'Verified')
    .map((entry) => entry.domain);

  // Approvals live under Operations, one click away. That is fine until a grant
  // turns approval on: the agent then pauses on every action, and the place to
  // unpause it is the tab that is not on screen. This is the pointer from the
  // decision to its consequence.
  const { data: approvals } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentApprovals(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-approvals', orgSlug, tenantSlug, agentId],
  });
  const { data: tools, isLoading: isLoadingTools } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantTools(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-tools', orgSlug, tenantSlug],
  });

  // Only services that pin an audience: a task token is let into a service
  // by naming its audience, so one without has nothing for a grant to name.
  const { data: services } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantServices(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-services', orgSlug, tenantSlug],
  });
  const appOptions = useMemo(
    () =>
      (services?.items ?? [])
        .filter((service) => service.expectedAudience)
        .map((service) => ({ label: service.name, value: service.id })),
    [services],
  );
  const appNames = useMemo(
    () => Object.fromEntries((services?.items ?? []).map((service) => [service.id, service.name])),
    [services],
  );

  // Tools first: an operator granting agent access is usually thinking about a
  // tool, and the API permissions below it are the rarer, more abstract case.
  const capabilityOptions = [
    ...buildToolCapabilityOptions(tools ?? []),
    ...buildDelegationCapabilityOptions(permissionSet, permissionLabel),
  ];
  const authorizationCapabilityOptions = buildAuthorizationCapabilityOptions(
    permissionSet,
    permissionLabel,
  );
  const { data: agent } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getTenantAgent(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
  });

  const {
    data: delegations,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentDelegations(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-delegations', orgSlug, tenantSlug, agentId],
  });

  const awaitingCount = (approvals ?? []).filter(
    (approval) => approval.status === 'AwaitingApproval',
  ).length;
  const hasGatedGrant = (delegations ?? []).some(
    (delegation) => delegation.requiresApproval && !delegation.revoked,
  );

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateDelegations() {
    await queryClient.invalidateQueries({
      queryKey: ['agent-delegations', orgSlug, tenantSlug, agentId],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function handleDelegationAction(delegation: Delegation, action: DelegationAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    if (action === 'Revoke') {
      await revokeAgentDelegation(orgSlug, tenantSlug, agentId, delegation.delegationId);
      await invalidateDelegations();
    }
  }

  async function handleRevokeResource(delegationId: string, relation: string, resource: string) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await revokeDelegationResource(orgSlug, tenantSlug, agentId, delegationId, {
      relation,
      resource,
    });
    await invalidateDelegations();
  }

  const { isPending: isGrantingDelegation, mutate: submitGrantDelegation } = useMutation({
    mutationFn: (payload: GrantDelegationInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return grantAgentDelegation(orgSlug, tenantSlug, agentId, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.grantFailed')),
        type: 'error',
      });
    },
    onSuccess: async (result) => {
      setIsGrantModalOpen(false);
      setGrantedAccess({ expiresAt: result.expiresAt, taskToken: result.taskToken });
      await invalidateDelegations();
    },
  });

  const { isPending: isGrantingResource, mutateAsync: submitGrantResource } = useMutation({
    mutationFn: ({
      delegationId,
      payload,
    }: {
      delegationId: string;
      payload: GrantResourceAccessInput;
    }) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return grantDelegationResource(orgSlug, tenantSlug, agentId, delegationId, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.resourceGrantFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.resourceGranted'), type: 'success' });
      await invalidateDelegations();
    },
  });

  return (
    <>
      <DashboardDataCard
        actionLabel={t('give')}
        description={t('description')}
        errorMessage={errorMessage}
        secondaryActionLabel={t('testWithoutSending')}
        title={t('title')}
        onActionClick={canManageDelegations ? () => setIsGrantModalOpen(true) : undefined}
        onSecondaryActionClick={
          canCheckAuthorization ? () => setIsCheckAuthorizationOpen(true) : undefined
        }
      >
        {hasGatedGrant || awaitingCount ? (
          <Link
            href={approvalsPath}
            className="mb-3 flex items-center gap-2 rounded-lg border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange transition hover:bg-orange/15"
          >
            <span className="material-symbols-rounded text-sm!" aria-hidden>
              assignment_turned_in
            </span>
            <span>
              {awaitingCount ? t('waiting', { count: awaitingCount }) : t('gatedNotice')}
              {t('openApprovals')}
            </span>
          </Link>
        ) : null}

        <DelegationsTable
          agentName={agent?.name}
          appNames={appNames}
          canRevoke={canManageDelegations}
          delegations={delegations ?? []}
          isGrantingResource={isGrantingResource}
          isLoading={isLoading}
          onDelegationAction={handleDelegationAction}
          onGrantResource={(delegationId, payload) =>
            submitGrantResource({ delegationId, payload })
          }
          onRevokeResource={handleRevokeResource}
        />
      </DashboardDataCard>

      <GrantDelegationModal
        agentName={agent?.name}
        appOptions={appOptions}
        capabilityOptions={capabilityOptions}
        hasSigningKey={hasSigningKey}
        hasTools={Boolean(tools?.length)}
        isLoadingOptions={isLoadingTools}
        isPreparingSigningKey={isPreparingSigningKey}
        onPrepareSigningKey={prepareSigningKey}
        isSubmitting={isGrantingDelegation}
        open={isGrantModalOpen}
        onClose={() => setIsGrantModalOpen(false)}
        onSubmit={submitGrantDelegation}
      />

      <AccessGrantedModal
        agentName={agent?.name}
        gatewayHosts={gatewayHosts}
        granted={grantedAccess}
        onClose={() => setGrantedAccess(null)}
      />

      <CheckAuthorizationModal
        agentId={agentId}
        capabilityOptions={authorizationCapabilityOptions}
        open={isCheckAuthorizationOpen}
        orgSlug={orgSlug ?? ''}
        tenantSlug={tenantSlug}
        onClose={() => setIsCheckAuthorizationOpen(false)}
      />
    </>
  );
}
