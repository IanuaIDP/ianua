'use client';

import { useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { UnsavedChangesModal } from '@/components/dashboard/shared/unsaved-changes-modal';
import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { AppSignInCard } from '@/components/dashboard/tenant-detail/sections/services/app-sign-in-card';
import { DiscoveryFields } from '@/components/dashboard/tenant-detail/sections/services/discovery-fields';
import { StickySessionFields } from '@/components/dashboard/tenant-detail/sections/services/sticky-session-fields';
import { WeightedBackendsField } from '@/components/dashboard/tenant-detail/sections/services/weighted-backends-field';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { DEFAULT_DISCOVERY_REFRESH_SECS } from '@/constants/service';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useUnsavedChangesGuard } from '@/hooks/dashboard/use-unsaved-changes-guard';
import {
  createTenantService,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantService,
  updateTenantService,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { ServiceFormSchema, type ServiceFormInput } from '@/schemas/service-schemas';
import type { GatewayService } from '@/types/gateway-service';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

const emptyFormValues: ServiceFormInput = {
  additionalBackends: [],
  discoveryEnabled: false,
  discoveryKind: 'srv',
  discoveryName: '',
  discoveryRefreshSecs: String(DEFAULT_DISCOVERY_REFRESH_SECS),
  expectedAudience: '',
  healthCheckEnabled: false,
  healthCheckPath: '/healthz',
  healthCheckTimings: null,
  name: '',
  preserveHost: true,
  requireClientCertificate: false,
  stickySessionKind: 'None',
  stickySessionValue: '',
  timeoutSecs: '30',
  upstreamUrl: '',
};

function toFormValues(service: GatewayService): ServiceFormInput {
  const stickySession = service.stickySession;

  return {
    additionalBackends: service.additionalBackends.map((backend) => ({
      url: backend.url,
      weight: String(backend.weight),
    })),
    discoveryEnabled: Boolean(service.discoveryName),
    discoveryKind: service.discoveryKind,
    discoveryName: service.discoveryName,
    discoveryRefreshSecs: String(service.discoveryRefreshSecs),
    expectedAudience: service.expectedAudience,
    healthCheckEnabled: service.healthCheckEnabled,
    healthCheckPath: service.healthCheckPath,
    healthCheckTimings: service.healthCheckTimings,
    name: service.name,
    preserveHost: service.preserveHost,
    requireClientCertificate: service.requireClientCertificate,
    stickySessionKind: stickySession?.kind ?? 'None',
    stickySessionValue:
      stickySession && (stickySession.kind === 'Cookie' || stickySession.kind === 'Header')
        ? stickySession.value
        : '',
    timeoutSecs: String(service.timeoutSecs),
    upstreamUrl: service.upstreamUrl,
  };
}

type ServiceFormPageProps = {
  mode: 'create' | 'edit';
};

export function ServiceFormPage({ mode }: ServiceFormPageProps) {
  const t = useTranslations('dashboard.services.form');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const router = useRouter();
  const params = useParams();
  const serviceId =
    mode === 'edit' ? decodeURIComponent(String(params.serviceId ?? '')) : undefined;
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();

  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<ServiceFormInput>({
    resolver: zodResolver(ServiceFormSchema),
    defaultValues: emptyFormValues,
  });

  const {
    data: existingService,
    error: serviceError,
    isLoading: isLoadingService,
  } = useQuery({
    enabled: mode === 'edit' && Boolean(orgSlug && tenantSlug && serviceId),
    queryFn: () => getTenantService(orgSlug ?? '', tenantSlug, serviceId ?? ''),
    queryKey: ['tenant-service', orgSlug, tenantSlug, serviceId],
  });

  useEffect(() => {
    if (!existingService) {
      return;
    }

    reset(toFormValues(existingService));
  }, [existingService, reset]);

  const servicesPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'services',
    'services',
  );
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const leaveGuard = useUnsavedChangesGuard(isDirty);

  async function invalidateServices() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-services', orgSlug, tenantSlug] });

    if (orgSlug) {
      await invalidateAuditLogQueries(queryClient, orgSlug);
    }
  }

  const { isPending: isCreating, mutate: submitCreateService } = useMutation({
    mutationFn: (payload: ServiceFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantService(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateServices();
      router.push(servicesPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdating, mutate: submitUpdateService } = useMutation({
    mutationFn: (payload: ServiceFormInput) => {
      if (!orgSlug || !serviceId) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantService(orgSlug, tenantSlug, serviceId, payload);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateServices();
      router.push(servicesPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const isSubmitting = mode === 'create' ? isCreating : isUpdating;

  function handleFormSubmit(payload: ServiceFormInput) {
    if (mode === 'create') {
      submitCreateService(payload);
      return;
    }

    submitUpdateService(payload);
  }

  const pageTitle = mode === 'create' ? t('newTitle') : t('editTitle');

  const headerTrail = isTenantView
    ? [{ href: servicesPath, icon: 'dns' }, { title: pageTitle }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: servicesPath, title: navLabels.label('Services') },
        { title: pageTitle },
      ];

  const serviceErrorMessage = deriveErrorMessage([
    serviceError,
    getApiErrorMessage(serviceError, t('loadFailed')),
  ]);

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Services"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={(item) =>
            leaveGuard.leaveTo(getTenantManagementTabHref(tenantSlug, item.label))
          }
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <div className="mx-auto w-full max-w-360 overflow-hidden rounded-lg border border-borderGray bg-cardBg">
            <div className="flex flex-col gap-4 border-b border-borderGray p-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <h1 className="text-base font-bold text-white">{pageTitle}</h1>
                <p className="mt-1 text-xs text-textGray">
                  {mode === 'create' ? t('createDescription') : t('editDescription')}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2.5">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => leaveGuard.leaveTo(servicesPath)}
                  className="w-auto border-borderGray bg-cardBg px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
                >
                  {t('cancel')}
                </Button>
                <Button
                  type="button"
                  isLoading={isSubmitting}
                  disabled={!isDirty || (mode === 'edit' && isLoadingService)}
                  onClick={handleSubmit(handleFormSubmit)}
                  className="w-auto bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple"
                >
                  {mode === 'create' ? t('add') : t('save')}
                </Button>
              </div>
            </div>

            <div className="p-4">
              {mode === 'edit' && isLoadingService ? (
                <p className="py-10 text-center text-xs font-medium text-textGray">
                  {t('loading')}
                </p>
              ) : mode === 'edit' && serviceErrorMessage ? (
                <p className="py-10 text-center text-xs font-medium text-error">
                  {serviceErrorMessage}
                </p>
              ) : (
                <div className="flex flex-col gap-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <Input
                      label={t('name')}
                      placeholder={t('namePlaceholder')}
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('name')}
                      error={errors.name}
                      disabled={isSubmitting}
                    />
                    <Input
                      label={t('timeout')}
                      placeholder="30"
                      type="number"
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('timeoutSecs')}
                      error={errors.timeoutSecs}
                      disabled={isSubmitting}
                    />
                  </div>

                  <Input
                    label={t('upstream')}
                    placeholder="http://api.example.com"
                    hint={t('upstreamHint')}
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    {...register('upstreamUrl')}
                    error={errors.upstreamUrl}
                    disabled={isSubmitting}
                  />

                  <WeightedBackendsField
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    setValue={setValue}
                  />

                  <DiscoveryFields
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    register={register}
                  />

                  <Input
                    label={t('audience')}
                    placeholder="https://api.example.com"
                    hint={t('audienceHint')}
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    {...register('expectedAudience')}
                    error={errors.expectedAudience}
                    disabled={isSubmitting}
                  />

                  <StickySessionFields
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    register={register}
                  />

                  <div className="flex flex-col gap-3">
                    <Checkbox
                      label={t('probe')}
                      {...register('healthCheckEnabled')}
                      disabled={isSubmitting}
                    />
                    <Input
                      label={t('probePath')}
                      placeholder="/health"
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('healthCheckPath')}
                      error={errors.healthCheckPath}
                      disabled={isSubmitting}
                    />
                  </div>

                  <Checkbox
                    label={t('preserveHost')}
                    {...register('preserveHost')}
                    disabled={isSubmitting}
                  />

                  <div className="flex flex-col gap-1">
                    <Checkbox
                      label={t('mtls')}
                      {...register('requireClientCertificate')}
                      disabled={isSubmitting}
                    />
                    <p className="pl-6 text-xs text-textGray">{t('mtlsHint')}</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {mode === 'edit' && existingService && orgSlug ? (
            <AppSignInCard orgSlug={orgSlug} service={existingService} tenantSlug={tenantSlug} />
          ) : null}
        </main>
      </div>
      <UnsavedChangesModal guard={leaveGuard} />
    </div>
  );
}
