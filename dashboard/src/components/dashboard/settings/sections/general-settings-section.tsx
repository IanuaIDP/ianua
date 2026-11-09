'use client';

import { useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getOrganization,
  updateOrganization,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  OrganizationSettingsGeneralSchema,
  type OrganizationSettingsInput,
} from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import { useOrganizationStore } from '@/store/organization-store';

const organizationDefaultValues: OrganizationSettingsInput = {
  contactEmail: '',
  displayName: '',
  name: '',
  urlSlug: '',
};

export function GeneralSettingsSection() {
  const t = useTranslations('dashboard.settings.general');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { canManageOrganization } = useOrgAccess();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const updateUser = useAuthStore((state) => state.updateUser);
  const setOrganization = useOrganizationStore((state) => state.setOrganization);
  const {
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<OrganizationSettingsInput>({
    resolver: zodResolver(OrganizationSettingsGeneralSchema),
    defaultValues: organizationDefaultValues,
    mode: 'onBlur',
  });
  const {
    data: organization,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getOrganization(organizationSlug ?? ''),
    queryKey: ['organization', organizationSlug],
  });
  const { isPending: isUpdatingOrganization, mutate: submitOrganizationUpdate } = useMutation({
    mutationFn: (payload: OrganizationSettingsInput) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateOrganization(organizationSlug, payload);
    },
    onSuccess: async (updatedOrganization) => {
      setOrganization(updatedOrganization);
      updateUser({ organizationName: updatedOrganization.name });
      reset({
        contactEmail: updatedOrganization.contactEmail,
        displayName: updatedOrganization.displayName,
        name: updatedOrganization.name,
        urlSlug: updatedOrganization.slug,
      });
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['organization', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  useEffect(() => {
    if (!organization) {
      return;
    }

    reset({
      contactEmail: organization.contactEmail,
      displayName: organization.displayName,
      name: organization.name,
      urlSlug: organization.slug,
    });
    setOrganization(organization);
  }, [organization, reset, setOrganization]);

  const handleOrganizationSubmit = (data: OrganizationSettingsInput) => {
    if (!isDirty) {
      return;
    }

    submitOrganizationUpdate(data);
  };

  const discardOrganizationChanges = () => {
    reset({
      contactEmail: organization?.contactEmail ?? organizationDefaultValues.contactEmail,
      displayName: organization?.displayName ?? organizationDefaultValues.displayName,
      name: organization?.name ?? organizationDefaultValues.name,
      urlSlug: organization?.slug ?? organizationDefaultValues.urlSlug,
    });
  };

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  return (
    <div className="flex flex-col gap-4">
      <SettingsCard
        title={t('organization.title')}
        description={
          canManageOrganization
            ? t('organization.descriptionOwner')
            : t('organization.descriptionMember')
        }
      >
        <form className="space-y-6" onSubmit={handleSubmit(handleOrganizationSubmit)}>
          <div className="grid gap-4 md:grid-cols-2">
            <Input
              label={t('organization.name')}
              placeholder={t('organization.namePlaceholder')}
              containerClassName="mb-0"
              {...register('name')}
              error={errors.name}
              disabled={!canManageOrganization || isLoading || isUpdatingOrganization}
            />
            <Input
              label={t('organization.displayName')}
              placeholder={t('organization.namePlaceholder')}
              containerClassName="mb-0"
              {...register('displayName')}
              error={errors.displayName}
              disabled={!canManageOrganization || isLoading || isUpdatingOrganization}
            />
            <Input
              label={t('organization.contactEmail')}
              placeholder={t('organization.contactEmailPlaceholder')}
              type="email"
              containerClassName="mb-0"
              {...register('contactEmail')}
              error={errors.contactEmail}
              disabled={!canManageOrganization || isLoading || isUpdatingOrganization}
            />
            <Input
              label={t('organization.slug')}
              placeholder={t('organization.slugPlaceholder')}
              hint={t('organization.slugHint')}
              containerClassName="mb-0"
              {...register('urlSlug')}
              error={errors.urlSlug}
              disabled
            />
          </div>
          {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}

          {canManageOrganization ? (
            <div className="flex items-center gap-4">
              <Button
                type="submit"
                isLoading={isUpdatingOrganization}
                disabled={isLoading || !isDirty || Boolean(errorMessage)}
                className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
              >
                {t('save')}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={isLoading || !isDirty || isUpdatingOrganization}
                onClick={discardOrganizationChanges}
                className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
              >
                {t('discard')}
              </Button>
            </div>
          ) : null}
        </form>
      </SettingsCard>

      <SettingsCard title={t('details.title')}>
        <div className="grid overflow-hidden rounded-lg border border-borderGray md:grid-cols-3">
          <div className="px-4 py-3 md:border-r md:border-borderGray">
            <p className="text-xs font-medium text-textGray">{t('details.status')}</p>
            <DashboardStatusBadge status={organization?.status ?? 'Active'} />
          </div>
          <div className="px-4 py-3 md:border-r md:border-borderGray">
            <p className="text-xs font-medium text-textGray">{t('details.tenants')}</p>
            <span className="mt-1 text-sm font-bold text-white">
              {isLoading ? t('loading') : (organization?.tenantsCount ?? t('notAvailable'))}
            </span>
          </div>
          <div className="px-4 py-3">
            <p className="text-xs font-medium text-textGray">{t('details.created')}</p>
            <span className="mt-1 text-sm font-bold text-white">
              {isLoading ? t('loading') : (organization?.created ?? t('notAvailable'))}
            </span>
          </div>
        </div>
      </SettingsCard>
    </div>
  );
}
