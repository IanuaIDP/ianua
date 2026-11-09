'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { CreateCredentialModal } from '@/components/dashboard/tenant-detail/sections/agents/credentials/create-credential-modal';
import { CredentialsTable } from '@/components/dashboard/tenant-detail/sections/agents/credentials/credentials-table';
import { EditAttestationPolicyModal } from '@/components/dashboard/tenant-detail/sections/agents/credentials/edit-attestation-policy-modal';
import { RotateCredentialModal } from '@/components/dashboard/tenant-detail/sections/agents/credentials/rotate-credential-modal';
import { useNotification } from '@/components/ui/notifications';
import { useAgentText } from '@/hooks/dashboard/use-agent-text';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import {
  deriveErrorMessage,
  executeAgentCredentialAction,
  executeTenantAgentAction,
  getAgentCredentials,
  getApiErrorMessage,
  getTenantAgent,
  mintAgentCredential,
  rotateAgentCredential,
  setTenantAgentAttestationPolicy,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type {
  CreateCredentialInput,
  EditAttestationPolicyInput,
  RotateCredentialInput,
} from '@/schemas/credential-schemas';
import type { Credential, CredentialAction } from '@/types/credential';
import { normalizeAttestationMethods } from '@/utils/credential';

export function CredentialsSection() {
  const t = useTranslations('dashboard.credentials');
  const tAgents = useTranslations('dashboard.agents');
  const tErrors = useTranslations('common.errors');
  const { actionModalContent, reattestInterval } = useAgentText();
  const { agentId, orgSlug, tenantSlug } = useAgentRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateAgent = hasPermission('Agents', 'Update');
  const canDeleteCredential = hasPermission('Agents', 'Delete');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();

  const [isEditPolicyOpen, setIsEditPolicyOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isRequireReattestOpen, setIsRequireReattestOpen] = useState(false);
  const [rotatingCredential, setRotatingCredential] = useState<Credential | null>(null);

  const { data: agent } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getTenantAgent(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
  });

  const {
    data: credentials,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentCredentials(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-credentials', orgSlug, tenantSlug, agentId],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const activeCredentialCount = (credentials ?? []).filter(
    (credential) => credential.status === 'Active',
  ).length;

  async function invalidateCredentials() {
    await queryClient.invalidateQueries({
      queryKey: ['agent-credentials', orgSlug, tenantSlug, agentId],
    });
    await queryClient.invalidateQueries({
      queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isSavingPolicy, mutate: submitAttestationPolicy } = useMutation({
    mutationFn: (payload: EditAttestationPolicyInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return setTenantAgentAttestationPolicy(
        orgSlug,
        tenantSlug,
        agentId,
        payload.methods,
        Number(payload.reattestIntervalSeconds),
        payload.allowedOrigins,
      );
    },
    onSuccess: async () => {
      setIsEditPolicyOpen(false);
      showNotification({ message: t('toasts.policySaved'), type: 'success' });
      await invalidateCredentials();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.policySaveFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isCreatingCredential, mutate: submitCreateCredential } = useMutation({
    mutationFn: (payload: CreateCredentialInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return mintAgentCredential(
        orgSlug,
        tenantSlug,
        agentId,
        payload.algorithm,
        payload.publicKey,
        payload.expiresInSeconds ? Number(payload.expiresInSeconds) : undefined,
      );
    },
    onSuccess: async () => {
      setIsCreateModalOpen(false);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateCredentials();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isRotatingCredential, mutate: submitRotateCredential } = useMutation({
    mutationFn: (payload: RotateCredentialInput) => {
      if (!orgSlug || !rotatingCredential) {
        throw new Error(tErrors('organizationMissing'));
      }

      return rotateAgentCredential(
        orgSlug,
        tenantSlug,
        agentId,
        rotatingCredential.id,
        payload.algorithm,
        payload.publicKey,
      );
    },
    onSuccess: async () => {
      setRotatingCredential(null);
      showNotification({ message: t('toasts.rotated'), type: 'success' });
      await invalidateCredentials();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.rotateFailed')),
        type: 'error',
      });
    },
  });

  async function handleCredentialAction(credential: Credential, action: CredentialAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeAgentCredentialAction(orgSlug, tenantSlug, agentId, credential, action);
    await invalidateCredentials();
  }

  const { isPending: isRequiringReattest, mutate: submitRequireReattest } = useMutation({
    mutationFn: () => {
      if (!orgSlug || !agent) {
        throw new Error(tErrors('organizationMissing'));
      }

      return executeTenantAgentAction(orgSlug, tenantSlug, agent, 'RequireReattestation');
    },
    onSuccess: async () => {
      setIsRequireReattestOpen(false);
      showNotification({
        message: tAgents('lifecycle.success.RequireReattestation'),
        type: 'success',
      });
      await invalidateCredentials();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, tAgents('lifecycle.failed')),
        type: 'error',
      });
    },
  });

  const attestationMethods = agent?.attestationMethods ?? [];
  const hasAttestationPolicy = attestationMethods.length > 0;
  const requireReattestContent = agent ? actionModalContent(agent).RequireReattestation : null;

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border border-borderGray bg-cardBg px-4 py-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-sm font-bold text-white">{t('policy.title')}</h2>
          <div className="flex flex-wrap items-center gap-2">
            {canUpdateAgent ? (
              <button
                type="button"
                onClick={() => setIsEditPolicyOpen(true)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 border border-borderGray text-xs font-medium text-white transition hover:bg-hoverBg"
              >
                <span className="material-symbols-rounded text-sm!" aria-hidden>
                  edit
                </span>
                {t('policy.edit')}
              </button>
            ) : null}
            {canUpdateAgent ? (
              <button
                type="button"
                onClick={() => setIsRequireReattestOpen(true)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md border border-focus px-3 text-xs font-medium text-focus transition hover:bg-focus/10"
              >
                <span className="material-symbols-rounded text-sm!" aria-hidden>
                  fingerprint
                </span>
                {t('policy.require')}
              </button>
            ) : null}
          </div>
        </div>

        <dl className="mt-3 grid overflow-hidden rounded-[10px] border border-borderGray text-sm sm:grid-cols-3">
          <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
            <dt className="text-textGray">{t('policy.trustedMethods')}</dt>
            <dd className="mt-1 text-base font-bold text-white">
              {hasAttestationPolicy
                ? attestationMethods.map((method) => method.toLowerCase()).join(', ')
                : tAgents('notConfigured')}
            </dd>
          </div>
          <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
            <dt className="text-textGray">{t('policy.reattestEvery')}</dt>
            <dd className="mt-1 text-base font-bold text-white">
              {reattestInterval(agent?.reattestIntervalSeconds ?? null)}
            </dd>
          </div>
          <div className="flex flex-col justify-center px-4 py-3">
            <dt className="text-textGray">{t('policy.activeCredentials')}</dt>
            <dd className="mt-1 text-base font-bold text-white">{activeCredentialCount}</dd>
          </div>
        </dl>
      </div>

      <DashboardDataCard
        actionLabel={t('create')}
        description={hasAttestationPolicy ? t('descriptionAttested') : t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={
          canUpdateAgent && !hasAttestationPolicy ? () => setIsCreateModalOpen(true) : undefined
        }
      >
        <CredentialsTable
          canRevoke={canDeleteCredential}
          canRotate={canUpdateAgent && !hasAttestationPolicy}
          credentials={credentials ?? []}
          isLoading={isLoading}
          onCredentialAction={handleCredentialAction}
          onRotate={setRotatingCredential}
        />
      </DashboardDataCard>

      <EditAttestationPolicyModal
        defaultValues={{
          methods: normalizeAttestationMethods(attestationMethods),
          reattestIntervalSeconds: agent?.reattestIntervalSeconds
            ? String(agent.reattestIntervalSeconds)
            : '',
          allowedOrigins: agent?.attestationOrigins ?? [],
        }}
        isSubmitting={isSavingPolicy}
        open={isEditPolicyOpen}
        onClose={() => setIsEditPolicyOpen(false)}
        onSubmit={submitAttestationPolicy}
      />

      <CreateCredentialModal
        isSubmitting={isCreatingCredential}
        open={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreateCredential}
      />

      <RotateCredentialModal
        credential={rotatingCredential}
        isSubmitting={isRotatingCredential}
        onClose={() => setRotatingCredential(null)}
        onSubmit={submitRotateCredential}
      />

      <ActionConfirmModal
        confirmationValue=""
        content={isRequireReattestOpen ? requireReattestContent : null}
        isSubmitting={isRequiringReattest}
        onClose={() => setIsRequireReattestOpen(false)}
        onConfirm={() => submitRequireReattest()}
        onConfirmationChange={() => {}}
      />
    </div>
  );
}
