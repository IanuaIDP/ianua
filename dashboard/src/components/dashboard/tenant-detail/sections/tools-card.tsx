'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { RegisterToolModal } from '@/components/dashboard/tenant-detail/sections/tools/register-tool-modal';
import { ToolSchemaModal } from '@/components/dashboard/tenant-detail/sections/tools/tool-schema-modal';
import { ToolsTable } from '@/components/dashboard/tenant-detail/sections/tools/tools-table';
import { useNotification } from '@/components/ui/notifications';
import { canHoldExampleTools, exampleToolsFor } from '@/constants/example-tools';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  executeTenantToolAction,
  getApiErrorMessage,
  getTenantRoutes,
  getTenantTools,
  registerTenantTool,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { RegisterToolInput } from '@/schemas/tool-schemas';
import type { Tool, ToolAction } from '@/types/tool';

export function ToolsCard() {
  const t = useTranslations('dashboard.tools');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canRegisterTool = hasPermission('Agents', 'Manage');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [schemaTool, setSchemaTool] = useState<Tool | null>(null);

  const {
    data: tools,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantTools(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-tools', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  // Registers whichever examples are missing, so pressing it twice is safe and
  // a half-finished set fills itself in rather than failing on the first clash.
  const { data: routeList } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantRoutes(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-routes', orgSlug, tenantSlug, 'tool-picker'],
  });
  const routeOptions = (routeList?.items ?? []).map((route) => ({
    label: route.name,
    value: route.id,
  }));
  const exampleRoute = routeList?.items.find(canHoldExampleTools);

  const { isPending: isAddingExamples, mutate: addExampleTools } = useMutation({
    mutationFn: async () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (!exampleRoute) {
        throw new Error(t('examplesNeedRoute'));
      }

      const existing = new Set((tools ?? []).map((tool) => tool.name));
      const missing = exampleToolsFor(exampleRoute).filter((tool) => !existing.has(tool.name));

      for (const tool of missing) {
        await registerTenantTool(orgSlug, tenantSlug, tool);
      }

      return missing.length;
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.examplesFailed')),
        type: 'error',
      });
    },
    onSuccess: async (added) => {
      showNotification({
        message: added ? t('toasts.examplesAdded', { count: added }) : t('toasts.examplesExist'),
        type: added ? 'success' : 'default',
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-tools', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  const { isPending: isRegisteringTool, mutate: submitRegisterTool } = useMutation({
    mutationFn: (payload: RegisterToolInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return registerTenantTool(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsRegisterModalOpen(false);
      showNotification({ message: t('toasts.registered'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenant-tools', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.registerFailed')),
        type: 'error',
      });
    },
  });

  async function handleToolAction(tool: Tool, action: ToolAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantToolAction(orgSlug, tenantSlug, tool, action);
    await queryClient.invalidateQueries({ queryKey: ['tenant-tools', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('register')}
        description={t('description')}
        errorMessage={errorMessage}
        secondaryActionLabel={isAddingExamples ? t('adding') : t('addExamples')}
        title={t('title')}
        onActionClick={canRegisterTool ? () => setIsRegisterModalOpen(true) : undefined}
        onSecondaryActionClick={
          canRegisterTool && !isAddingExamples ? () => addExampleTools() : undefined
        }
      >
        <ToolsTable
          isLoading={isLoading}
          tools={tools ?? []}
          onToolAction={handleToolAction}
          onViewSchema={setSchemaTool}
        />
      </DashboardDataCard>

      <RegisterToolModal
        isSubmitting={isRegisteringTool}
        open={isRegisterModalOpen}
        routeOptions={routeOptions}
        onClose={() => setIsRegisterModalOpen(false)}
        onSubmit={submitRegisterTool}
      />
      <ToolSchemaModal tool={schemaTool} onClose={() => setSchemaTool(null)} />
    </>
  );
}
