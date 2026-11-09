'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { useNotification } from '@/components/ui/notifications';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  archiveTenant,
  deleteTenant,
  getApiErrorMessage,
  getTenant,
  reactivateTenant,
  suspendTenant,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';

type TenantStatusRedirectPage = 'tenant-archived' | 'tenant-deleted' | 'tenant-suspended';

export function useTenantLifecycleActions() {
  const t = useTranslations('dashboard.tenants.toasts');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();

  const [isSuspendModalOpen, setIsSuspendModalOpen] = useState(false);
  const [suspendConfirmationValue, setSuspendConfirmationValue] = useState('');
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [deleteConfirmationValue, setDeleteConfirmationValue] = useState('');
  const [isArchiveModalOpen, setIsArchiveModalOpen] = useState(false);
  const [archiveConfirmationValue, setArchiveConfirmationValue] = useState('');

  const { data: tenant } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenant(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-detail', orgSlug, tenantSlug],
  });
  const tenantName = tenant?.displayName || tenantSlug;
  const isStatusArchived = tenant?.status === 'Archived';
  const canRestoreAccess = !isTenantView && tenant?.status === 'Suspended';

  function isDangerZoneButtonDisabled(isPending: boolean) {
    return isTenantView ? false : !tenant || isPending;
  }

  async function invalidateTenantQueries() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-detail', orgSlug, tenantSlug] });
    await queryClient.invalidateQueries({ queryKey: ['tenant-metrics', orgSlug, tenantSlug] });
    await queryClient.invalidateQueries({ queryKey: ['tenants', orgSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function redirectToStatusPage(page: TenantStatusRedirectPage) {
    const params = new URLSearchParams({ org: orgSlug ?? '', tenant: tenantSlug });
    window.location.assign(`/${page}?${params.toString()}`);
  }

  const { isPending: isSuspendingTenant, mutate: submitSuspendTenant } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return suspendTenant(orgSlug, tenantSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('suspendFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      if (isTenantView) {
        redirectToStatusPage('tenant-suspended');
        return;
      }

      setIsSuspendModalOpen(false);
      setSuspendConfirmationValue('');
      showNotification({ message: t('suspended'), type: 'success' });
      await invalidateTenantQueries();
    },
  });

  const { isPending: isRestoringTenant, mutate: submitRestoreTenant } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return reactivateTenant(orgSlug, tenantSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('restoreFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setIsRestoreModalOpen(false);
      showNotification({ message: t('restored'), type: 'success' });
      await invalidateTenantQueries();
    },
  });

  const { isPending: isDeletingTenant, mutate: submitDeleteTenant } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return deleteTenant(orgSlug, tenantSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('deleteFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      if (isTenantView) {
        redirectToStatusPage('tenant-deleted');
        return;
      }

      setIsDeleteModalOpen(false);
      setDeleteConfirmationValue('');
      showNotification({ message: t('deleted'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenants', orgSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      router.push('/tenants');
    },
  });

  const { isPending: isArchivingTenant, mutate: submitArchiveTenant } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return archiveTenant(orgSlug, tenantSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('archiveFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      if (isTenantView) {
        redirectToStatusPage('tenant-archived');
        return;
      }

      setIsArchiveModalOpen(false);
      setArchiveConfirmationValue('');
      showNotification({ message: t('archived'), type: 'success' });
      await invalidateTenantQueries();
    },
  });

  function closeSuspendModal() {
    if (isSuspendingTenant) {
      return;
    }

    setIsSuspendModalOpen(false);
    setSuspendConfirmationValue('');
  }

  function closeRestoreModal() {
    if (isRestoringTenant) {
      return;
    }

    setIsRestoreModalOpen(false);
  }

  function closeDeleteModal() {
    if (isDeletingTenant) {
      return;
    }

    setIsDeleteModalOpen(false);
    setDeleteConfirmationValue('');
  }

  function closeArchiveModal() {
    if (isArchivingTenant) {
      return;
    }

    setIsArchiveModalOpen(false);
    setArchiveConfirmationValue('');
  }

  return {
    canRestoreAccess,
    isDangerZoneButtonDisabled,
    isStatusArchived,
    isTenantView,
    tenant,
    tenantName,
    archive: {
      closeModal: closeArchiveModal,
      confirmationValue: archiveConfirmationValue,
      isModalOpen: isArchiveModalOpen,
      isSubmitting: isArchivingTenant,
      openModal: () => setIsArchiveModalOpen(true),
      setConfirmationValue: setArchiveConfirmationValue,
      submit: submitArchiveTenant,
    },
    delete: {
      closeModal: closeDeleteModal,
      confirmationValue: deleteConfirmationValue,
      isModalOpen: isDeleteModalOpen,
      isSubmitting: isDeletingTenant,
      openModal: () => setIsDeleteModalOpen(true),
      setConfirmationValue: setDeleteConfirmationValue,
      submit: submitDeleteTenant,
    },
    restore: {
      closeModal: closeRestoreModal,
      isModalOpen: isRestoreModalOpen,
      isSubmitting: isRestoringTenant,
      openModal: () => setIsRestoreModalOpen(true),
      submit: submitRestoreTenant,
    },
    suspend: {
      closeModal: closeSuspendModal,
      confirmationValue: suspendConfirmationValue,
      isModalOpen: isSuspendModalOpen,
      isSubmitting: isSuspendingTenant,
      openModal: () => setIsSuspendModalOpen(true),
      setConfirmationValue: setSuspendConfirmationValue,
      submit: submitSuspendTenant,
    },
  };
}

export type TenantLifecycleActions = ReturnType<typeof useTenantLifecycleActions>;
