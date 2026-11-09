'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { CreatePipelineModal } from '@/components/dashboard/tenant-detail/sections/pipeline/create-pipeline-modal';
import { PipelinesTable } from '@/components/dashboard/tenant-detail/sections/pipeline/pipelines-table';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantPipeline,
  deriveErrorMessage,
  executePipelineAction,
  getApiErrorMessage,
  getTenantPipelines,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { PipelineAction, PipelineSummary } from '@/types/pipeline';
import { getPipelineManagementPath, getPipelinePath } from '@/utils/dashboard-routes';

export function PipelineCard() {
  const t = useTranslations('dashboard.pipelines');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdatePipeline = hasPermission('Pipeline', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  const {
    data: pipelines,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPipelines(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-pipelines', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidatePipelines() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-pipelines', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function goToPipeline(pipelineId: string) {
    if (!isTenantView) {
      router.push(getPipelineManagementPath(tenantSlug, pipelineId));
      return;
    }

    if (!orgSlug) {
      return;
    }

    router.push(getPipelinePath(orgSlug, tenantSlug, pipelineId));
  }

  const { isPending: isCreatingPipeline, mutate: submitCreatePipeline } = useMutation({
    mutationFn: (name: string) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantPipeline(orgSlug, tenantSlug, name);
    },
    onSuccess: async (pipelineId) => {
      setIsCreateModalOpen(false);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidatePipelines();
      goToPipeline(pipelineId);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  async function handlePipelineAction(pipeline: PipelineSummary, action: PipelineAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executePipelineAction(orgSlug, tenantSlug, pipeline.id, action);
    await invalidatePipelines();
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('create')}
        description={t('description')}
        errorMessage={errorMessage}
        isActionDisabled={isCreatingPipeline}
        title={t('title')}
        onActionClick={canUpdatePipeline ? () => setIsCreateModalOpen(true) : undefined}
      >
        <PipelinesTable
          canUpdatePipeline={canUpdatePipeline}
          isLoading={isLoading}
          pipelines={pipelines ?? []}
          onPipelineAction={handlePipelineAction}
          onSelect={(pipeline) => goToPipeline(pipeline.id)}
        />
      </DashboardDataCard>

      <CreatePipelineModal
        isSubmitting={isCreatingPipeline}
        open={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreatePipeline}
      />
    </>
  );
}
