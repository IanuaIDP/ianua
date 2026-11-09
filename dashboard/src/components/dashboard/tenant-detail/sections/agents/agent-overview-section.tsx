'use client';

import { useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { AgentLifecycleCard } from '@/components/dashboard/tenant-detail/sections/agents/agent-lifecycle-card';
import { AgentNextStepCard } from '@/components/dashboard/tenant-detail/sections/agents/agent-next-step-card';
import { TenantAgentFormModal } from '@/components/dashboard/tenant-detail/sections/agents/tenant-agent-form-modal';
import { useNotification } from '@/components/ui/notifications';
import { useAgentText } from '@/hooks/dashboard/use-agent-text';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import {
  getAgentCredentials,
  getAgentDelegations,
  getApiErrorMessage,
  getTenantAgent,
  getTenantAgents,
  getTenantUsers,
  updateTenantAgent,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TenantAgentFormInput } from '@/schemas/tenant-agent-schemas';
import { getBadgeColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { shortId } from '@/utils/tenant-agent';

export function AgentOverviewSection() {
  const t = useTranslations('dashboard.agents.overview');
  const tAgents = useTranslations('dashboard.agents');
  const tErrors = useTranslations('common.errors');
  const { ownerDisplay, reattestInterval } = useAgentText();
  const { agentId, orgSlug, tenantSlug } = useAgentRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateAgent = hasPermission('Agents', 'Update');
  const canDeleteAgent = hasPermission('Agents', 'Delete');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);

  const {
    data: agent,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getTenantAgent(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
  });

  const { data: usersList } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantUsers(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-users', orgSlug, tenantSlug, 'owner-lookup'],
  });
  const usersById = useMemo(
    () => new Map((usersList?.items ?? []).map((user) => [user.id, user])),
    [usersList],
  );

  const { data: delegations } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentDelegations(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-delegations', orgSlug, tenantSlug, agentId],
  });

  const { data: credentials } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentCredentials(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['agent-credentials', orgSlug, tenantSlug, agentId],
  });

  const { data: agentsList } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agent?.owner.kind === 'agent'),
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-agents', orgSlug, tenantSlug, undefined, undefined],
  });
  const agentsById = useMemo(
    () => new Map((agentsList ?? []).map((ownerAgent) => [ownerAgent.id, ownerAgent])),
    [agentsList],
  );

  const { isPending: isUpdatingAgent, mutate: submitUpdateAgent } = useMutation({
    mutationFn: (payload: TenantAgentFormInput) => {
      if (!orgSlug || !agent) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantAgent(orgSlug, tenantSlug, agent.id, payload);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, tAgents('toasts.updateFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsEditModalOpen(false);
      showNotification({ message: tAgents('toasts.updated'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-agents', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  if (isLoading) {
    return <p className="text-xs font-medium text-textGray">{t('loading')}</p>;
  }

  if (error || !agent) {
    return (
      <p className="text-xs font-medium text-error">{getApiErrorMessage(error, t('loadFailed'))}</p>
    );
  }

  const owner = ownerDisplay(agent.owner, usersById, agentsById);
  const hasAttestationPolicy = agent.attestationMethods.length > 0;

  return (
    <div className="mx-auto flex w-full max-w-360 flex-col gap-4">
      {agent.standing === 'Active' ? (
        <AgentNextStepCard
          agentId={agent.id}
          hasCredential={Boolean(credentials?.length)}
          hasDelegation={Boolean(delegations?.some((delegation) => !delegation.revoked))}
          tenantSlug={tenantSlug}
        />
      ) : null}

      <div className="grid items-stretch gap-4 md:grid-cols-2">
        <div className="flex flex-col overflow-hidden rounded-[10px] border border-primary bg-brand-gradient shadow-primary-line-glow">
          <div className="shrink-0 bg-brand-gradient py-2 text-center text-[10px] font-extrabold uppercase tracking-normal text-cardBg">
            {t('title')}
          </div>
          <div className="mx-1 mb-1 min-h-0 flex-1 overflow-hidden rounded-md bg-cardBg">
            <div className="flex h-full flex-col justify-between gap-3 rounded-md border border-borderGray bg-cardBg p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-focus/20 text-focus">
                    <span className="material-symbols-rounded">robot_2</span>
                  </span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate text-sm font-bold text-white">{agent.name}</p>
                      <DashboardStatusBadge status={agent.standing} />
                    </div>
                    <p className="mt-1 text-xs font-medium text-textGray">
                      {t('id', { id: shortId(agent.id) })}
                    </p>
                  </div>
                </div>
                {canUpdateAgent ? (
                  <button
                    type="button"
                    aria-label={t('edit')}
                    onClick={() => setIsEditModalOpen(true)}
                    className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
                  >
                    <span className="material-symbols-rounded text-lg!">edit</span>
                  </button>
                ) : null}
              </div>
              {agent.description ? (
                <p className="line-clamp-2 text-xs font-medium text-textGray">
                  {agent.description}
                </p>
              ) : null}
            </div>
          </div>
        </div>

        <div className="flex flex-col rounded-lg border border-borderGray bg-cardBg px-4 py-4">
          <h2 className="text-sm font-bold text-white">{t('attestation')}</h2>
          <dl className="mt-3 grid flex-1 overflow-hidden rounded-[10px] border border-borderGray text-sm sm:grid-cols-2">
            <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
              <dt className="text-textGray">{t('trustedMethods')}</dt>
              <dd className="mt-1 text-base font-bold text-white">
                {hasAttestationPolicy
                  ? agent.attestationMethods.map((method) => method.toUpperCase()).join(', ')
                  : tAgents('notConfigured')}
              </dd>
            </div>
            <div className="flex flex-col justify-center px-4 py-3">
              <dt className="text-textGray">{t('reattestEvery')}</dt>
              <dd className="mt-1 text-base font-bold text-white">
                {reattestInterval(agent.reattestIntervalSeconds)}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="rounded-lg border border-borderGray bg-cardBg px-4 py-4">
        <h2 className="text-sm font-bold text-white">{t('identity')}</h2>
        <dl className="mt-3 grid overflow-hidden rounded-[10px] border border-borderGray text-sm sm:grid-cols-3">
          <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
            <dt className="text-textGray">{t('owner')}</dt>
            <dd className="mt-1 flex min-w-0 items-center gap-2">
              <span
                className={cn(
                  'flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                  getBadgeColorClass(owner.seed),
                )}
              >
                {owner.initial}
              </span>
              <p className="truncate text-base font-bold text-white">{owner.name}</p>
            </dd>
          </div>
          <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
            <dt className="text-textGray">{t('created')}</dt>
            <dd className="mt-1 text-base font-bold text-white">{agent.created}</dd>
          </div>
          <div className="flex flex-col justify-center px-4 py-3">
            <dt className="text-textGray">{t('updated')}</dt>
            <dd className="mt-1 text-base font-bold text-white">{agent.updated}</dd>
          </div>
        </dl>
      </div>

      <AgentLifecycleCard
        agent={agent}
        canDelete={canDeleteAgent}
        canUpdate={canUpdateAgent}
        orgSlug={orgSlug ?? ''}
        tenantSlug={tenantSlug}
      />

      <TenantAgentFormModal
        defaultValues={{ description: agent.description, name: agent.name }}
        description={tAgents('editModal.description')}
        isSubmitting={isUpdatingAgent}
        open={isEditModalOpen}
        primaryActionLabel={tAgents('editModal.submit')}
        title={tAgents('editModal.title')}
        onClose={() => setIsEditModalOpen(false)}
        onSubmit={submitUpdateAgent}
      />
    </div>
  );
}
