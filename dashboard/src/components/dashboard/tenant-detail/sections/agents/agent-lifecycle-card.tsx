'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DangerZoneActionRow } from '@/components/dashboard/tenant-detail/sections/settings/danger-zone/danger-zone-action-row';
import { useNotification } from '@/components/ui/notifications';
import { useAgentText } from '@/hooks/dashboard/use-agent-text';
import {
  executeTenantAgentAction,
  getAgentBlastRadius,
  getApiErrorMessage,
  getTenantAgentActiveCredentialCount,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TenantAgent, TenantAgentAction } from '@/types/tenant-agent';

type AgentLifecycleCardProps = {
  agent: TenantAgent;
  canDelete: boolean;
  canUpdate: boolean;
  orgSlug: string;
  tenantSlug: string;
};

export function AgentLifecycleCard({
  agent,
  canDelete,
  canUpdate,
  orgSlug,
  tenantSlug,
}: AgentLifecycleCardProps) {
  const t = useTranslations('dashboard.agents.lifecycle');
  const tAgents = useTranslations('dashboard.agents');
  const { actionModalContent } = useAgentText();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [selectedAction, setSelectedAction] = useState<TenantAgentAction | null>(null);
  const [confirmationValue, setConfirmationValue] = useState('');

  const modalContent = selectedAction ? actionModalContent(agent)[selectedAction] : null;

  const { data: blastRadius, isLoading: isBlastRadiusLoading } = useQuery({
    enabled: selectedAction === 'Contain',
    queryFn: () => getAgentBlastRadius(orgSlug, tenantSlug, agent.id),
    queryKey: ['tenant-agent-blast-radius', orgSlug, tenantSlug, agent.id],
  });
  const { data: activeCredentialCount, isLoading: isCredentialCountLoading } = useQuery({
    enabled: selectedAction === 'Contain',
    queryFn: () => getTenantAgentActiveCredentialCount(orgSlug, tenantSlug, agent.id),
    queryKey: ['tenant-agent-credential-count', orgSlug, tenantSlug, agent.id],
  });
  const isBlastRadiusPreviewLoading = isBlastRadiusLoading || isCredentialCountLoading;

  const { isPending, mutate } = useMutation({
    mutationFn: (action: TenantAgentAction) =>
      executeTenantAgentAction(orgSlug, tenantSlug, agent, action),
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('failed')),
        type: 'error',
      });
    },
    onSuccess: async (_data, action) => {
      setSelectedAction(null);
      setConfirmationValue('');
      showNotification({ message: tAgents(`lifecycle.success.${action}`), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-agent', orgSlug, tenantSlug, agent.id],
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-agents', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  function openModal(action: TenantAgentAction) {
    setConfirmationValue('');
    setSelectedAction(action);
  }

  function closeModal() {
    if (isPending) {
      return;
    }

    setSelectedAction(null);
    setConfirmationValue('');
  }

  const isSuspended = agent.status === 'Suspended';
  const isRevoked = agent.status === 'Revoked';

  return (
    <>
      <SettingsCard title={t('title')} description={t('description')}>
        <div className="flex flex-col items-start overflow-hidden rounded-lg border border-borderGray">
          <DangerZoneActionRow
            label={isSuspended ? t('resume.label') : t('suspend.label')}
            description={isSuspended ? t('resume.description') : t('suspend.description')}
            buttonLabel={isSuspended ? t('resume.button') : t('suspend.button')}
            tone="warning"
            disabled={!canUpdate || isRevoked || isPending}
            onClick={() => (isSuspended ? mutate('Resume') : openModal('Suspend'))}
          />
          <DangerZoneActionRow
            label={t('reattest.label')}
            description={t('reattest.description')}
            buttonLabel={t('reattest.button')}
            tone="warning"
            disabled={!canUpdate || isRevoked || isPending}
            onClick={() => openModal('RequireReattestation')}
          />
          <DangerZoneActionRow
            label={t('contain.label')}
            description={t('contain.description')}
            buttonLabel={t('contain.button')}
            tone="danger"
            disabled={!canDelete || isRevoked || isPending}
            onClick={() => openModal('Contain')}
          />
          <DangerZoneActionRow
            label={t('revoke.label')}
            description={t('revoke.description')}
            buttonLabel={t('revoke.button')}
            tone="danger"
            isLast
            disabled={!canDelete || isRevoked || isPending}
            onClick={() => openModal('Revoke')}
          />
        </div>
      </SettingsCard>

      <ActionConfirmModal
        confirmationValue={confirmationValue}
        content={modalContent}
        extraContent={
          selectedAction === 'Contain' ? (
            <div>
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wide text-textGray">
                {t('blastRadius')}
              </p>
              <dl className="overflow-hidden rounded-[10px] border border-borderGray text-sm">
                <div className="flex flex-col border-b border-borderGray px-4 py-3">
                  <dt className="text-textGray">{t('delegations')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {isBlastRadiusPreviewLoading ? '...' : (blastRadius?.delegationCount ?? '—')}
                  </dd>
                </div>
                <div className="flex flex-col border-b border-borderGray px-4 py-3">
                  <dt className="text-textGray">{t('agents')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {isBlastRadiusPreviewLoading ? '...' : (blastRadius?.agentCount ?? '—')}
                  </dd>
                </div>
                <div className="flex flex-col px-4 py-3">
                  <dt className="text-textGray">{t('credentialsRevoked')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {isBlastRadiusPreviewLoading ? '...' : (activeCredentialCount ?? '—')}
                  </dd>
                </div>
              </dl>
            </div>
          ) : undefined
        }
        isSubmitting={isPending}
        onClose={closeModal}
        onConfirm={() => selectedAction && mutate(selectedAction)}
        onConfirmationChange={setConfirmationValue}
      />
    </>
  );
}
