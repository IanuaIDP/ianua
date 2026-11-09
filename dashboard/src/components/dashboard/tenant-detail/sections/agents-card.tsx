'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTabs } from '@/components/dashboard/shared/dashboard-tabs';
import { TenantAgentFormModal } from '@/components/dashboard/tenant-detail/sections/agents/tenant-agent-form-modal';
import { TenantAgentsTable } from '@/components/dashboard/tenant-detail/sections/agents/tenant-agents-table';
import { useNotification } from '@/components/ui/notifications';
import type { SelectOption } from '@/components/ui/Select';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  createTenantAgent,
  deriveErrorMessage,
  executeTenantAgentAction,
  getApiErrorMessage,
  getCurrentTenantUser,
  getTenantAgents,
  getTenantUsers,
  suspendAllTenantAgents,
  updateTenantAgent,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TenantAgentFormInput } from '@/schemas/tenant-agent-schemas';
import { useAuthStore } from '@/store/auth-store';
import type {
  TenantAgent,
  TenantAgentAction,
  TenantAgentSortField,
  TenantAgentTab,
} from '@/types/tenant-agent';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';
import { decodeOwnerValue, encodeOwnerValue } from '@/utils/tenant-agent';

const tenantAgentTabs: TenantAgentTab[] = ['All', 'Active', 'Suspended', 'Revoked'];

export function AgentsCard() {
  const t = useTranslations('dashboard.agents');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateAgent = hasPermission('Agents', 'Create');
  const canUpdateAgent = hasPermission('Agents', 'Update');
  const canDeleteAgent = hasPermission('Agents', 'Delete');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [activeTab, setActiveTab] = useState<TenantAgentTab>('All');
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    resetToFirstPage,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<TenantAgentSortField>();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [editingAgent, setEditingAgent] = useState<TenantAgent | null>(null);
  const [isStopAllOpen, setIsStopAllOpen] = useState(false);
  const [stopAllConfirmation, setStopAllConfirmation] = useState('');

  const {
    data: allAgents = [],
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug, { sortDirection, sortField }),
    queryKey: ['tenant-agents', orgSlug, tenantSlug, sortField, sortDirection],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const agentsById = useMemo(
    () => new Map(allAgents.map((agent) => [agent.id, agent])),
    [allAgents],
  );

  const { data: usersList } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantUsers(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-users', orgSlug, tenantSlug, 'owner-lookup'],
  });
  const usersById = useMemo(
    () => new Map((usersList?.items ?? []).map((user) => [user.id, user])),
    [usersList],
  );

  const isTenantSession = useAuthStore((state) => state.access === null);
  const { data: currentTenantUser } = useQuery({
    enabled: isTenantSession && Boolean(orgSlug && tenantSlug),
    queryFn: () => getCurrentTenantUser(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-current-user', orgSlug, tenantSlug],
  });
  const currentUserId = currentTenantUser?.id;
  const currentUserEmail = currentUserId ? usersById.get(currentUserId)?.email : undefined;

  const selfOwnerValue = currentUserId ? encodeOwnerValue('user', currentUserId) : '';
  const ownerOptions: SelectOption[] = [
    { label: currentUserEmail ?? t('you'), value: selfOwnerValue },
    ...allAgents
      .filter((agent) => agent.status !== 'Revoked')
      .map((agent) => ({ label: agent.name, value: encodeOwnerValue('agent', agent.id) })),
  ];

  const filteredAgents =
    activeTab === 'All' ? allAgents : allAgents.filter((agent) => agent.status === activeTab);
  const pageStart = Number(after ?? 0);
  const pageEnd = pageStart + rowsPerPage;
  const pageAgents = filteredAgents.slice(pageStart, pageEnd);
  const nextCursor = pageEnd < filteredAgents.length ? String(pageEnd) : null;

  async function invalidateAgents() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-agents', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isCreatingAgent, mutate: submitCreateAgent } = useMutation({
    mutationFn: (payload: TenantAgentFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      const owner = payload.ownerId ? decodeOwnerValue(payload.ownerId) : null;

      return createTenantAgent(orgSlug, tenantSlug, payload, owner);
    },
    onSuccess: async () => {
      setIsCreateModalOpen(false);
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateAgents();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdatingAgent, mutate: submitUpdateAgent } = useMutation({
    mutationFn: (payload: TenantAgentFormInput) => {
      if (!orgSlug || !editingAgent) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantAgent(orgSlug, tenantSlug, editingAgent.id, payload);
    },
    onSuccess: async () => {
      setEditingAgent(null);
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateAgents();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isStoppingAll, mutate: submitStopAll } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return suspendAllTenantAgents(orgSlug, tenantSlug);
    },
    onSuccess: async (suspendedCount) => {
      closeStopAll();
      showNotification({
        message: t('toasts.stopped', { count: suspendedCount }),
        type: 'success',
      });
      await invalidateAgents();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.stopFailed')),
        type: 'error',
      });
    },
  });

  function closeStopAll() {
    setIsStopAllOpen(false);
    setStopAllConfirmation('');
  }

  async function handleAgentAction(agent: TenantAgent, action: TenantAgentAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantAgentAction(orgSlug, tenantSlug, agent, action);
    await invalidateAgents();
  }

  function handleAgentClick(agent: TenantAgent) {
    if (!isTenantView) {
      router.push(getAgentManagementPath(tenantSlug, agent.id));
      return;
    }

    if (!orgSlug) {
      return;
    }

    router.push(getAgentPath(orgSlug, tenantSlug, agent.id));
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('create')}
        description={t('description')}
        errorMessage={errorMessage}
        footer={
          <DashboardPagination
            currentPage={currentPage}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="tenant-agents-rows-per-page"
            itemCount={pageAgents.length}
            nextCursor={nextCursor}
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        title={t('title')}
        tabs={
          <DashboardTabs
            activeTab={activeTab}
            tabs={tenantAgentTabs}
            onTabChange={(tab) => {
              setActiveTab(tab);
              resetToFirstPage();
            }}
          />
        }
        onActionClick={canCreateAgent ? () => setIsCreateModalOpen(true) : undefined}
        secondaryActionLabel={canDeleteAgent ? t('stopAll') : undefined}
        onSecondaryActionClick={canDeleteAgent ? () => setIsStopAllOpen(true) : undefined}
      >
        <TenantAgentsTable
          agents={pageAgents}
          agentsById={agentsById}
          canDeleteAgent={canDeleteAgent}
          canUpdateAgent={canUpdateAgent}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          usersById={usersById}
          onAgentAction={handleAgentAction}
          onAgentClick={handleAgentClick}
          onEditClick={setEditingAgent}
          onSortChange={handleSortChange}
        />
      </DashboardDataCard>

      <ActionConfirmModal
        confirmationValue={stopAllConfirmation}
        content={
          isStopAllOpen
            ? {
                title: t('stopAllModal.title'),
                description: t('stopAllModal.description'),
                primaryActionLabel: t('stopAllModal.submit'),
                confirmationPlaceholder: tenantSlug,
                confirmationValue: tenantSlug,
                warningNote: t('stopAllModal.warning'),
                warningTone: 'danger',
              }
            : null
        }
        isSubmitting={isStoppingAll}
        onClose={closeStopAll}
        onConfirm={() => submitStopAll()}
        onConfirmationChange={setStopAllConfirmation}
      />

      <TenantAgentFormModal
        defaultValues={{ description: '', name: '', ownerId: selfOwnerValue }}
        description={t('createModal.description')}
        isSubmitting={isCreatingAgent}
        open={isCreateModalOpen}
        ownerOptions={ownerOptions}
        primaryActionLabel={t('createModal.submit')}
        title={t('createModal.title')}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={submitCreateAgent}
      />
      <TenantAgentFormModal
        defaultValues={
          editingAgent
            ? { description: editingAgent.description, name: editingAgent.name }
            : undefined
        }
        description={t('editModal.description')}
        isSubmitting={isUpdatingAgent}
        open={Boolean(editingAgent)}
        primaryActionLabel={t('editModal.submit')}
        title={t('editModal.title')}
        onClose={() => setEditingAgent(null)}
        onSubmit={submitUpdateAgent}
      />
    </>
  );
}
