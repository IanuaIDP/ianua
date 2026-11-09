'use client';

import { useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { UnsavedChangesModal } from '@/components/dashboard/shared/unsaved-changes-modal';
import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { StreamBackendsField } from '@/components/dashboard/tenant-detail/sections/routes/stream-backends-field';
import { StreamSniField } from '@/components/dashboard/tenant-detail/sections/routes/stream-sni-field';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useNotification } from '@/components/ui/notifications';
import {
  DEFAULT_STREAM_CONNECT_SECS,
  DEFAULT_STREAM_IDLE_SECS,
  ROUTE_KIND_PARAM,
  STREAM_ROUTE_KIND,
  carriesSni,
  terminatesTls,
} from '@/constants/stream-route';
import { useStreamRouteOptions } from '@/hooks/dashboard/use-stream-route-options';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useUnsavedChangesGuard } from '@/hooks/dashboard/use-unsaved-changes-guard';
import {
  createTenantStreamRoute,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantStreamRoute,
  updateTenantStreamRoute,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { StreamRouteFormSchema, type StreamRouteFormInput } from '@/schemas/stream-route-schemas';
import type { StreamProtocol, StreamRoute } from '@/types/stream-route';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

const emptyFormValues: StreamRouteFormInput = {
  backends: [{ host: '', port: '', weight: '1' }],
  connectSecs: DEFAULT_STREAM_CONNECT_SECS,
  idleSecs: DEFAULT_STREAM_IDLE_SECS,
  listenPort: '',
  name: '',
  policy: 'public',
  protocol: 'tcp',
  sniNames: [],
  sniRestricted: false,
};

function toFormValues(route: StreamRoute): StreamRouteFormInput {
  return {
    backends: route.backends.map((backend) => ({
      host: backend.host,
      port: String(backend.port),
      weight: String(backend.weight),
    })),
    connectSecs: String(route.timeouts.connectSecs),
    idleSecs: String(route.timeouts.idleSecs),
    listenPort: String(route.listenPort),
    name: route.name,
    access: route.access,
    policy: route.policy,
    protocol: route.protocol,
    sniNames: route.sni.mode === 'only' ? route.sni.names : [],
    sniRestricted: route.sni.mode === 'only',
  };
}

type StreamRouteFormPageProps = {
  mode: 'create' | 'edit';
};

export function StreamRouteFormPage({ mode }: StreamRouteFormPageProps) {
  const t = useTranslations('dashboard.ports.form');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const { policyOptions, protocolHint, protocolOptions } = useStreamRouteOptions();
  const router = useRouter();
  const params = useParams();
  const routeId =
    mode === 'edit' ? decodeURIComponent(String(params.streamRouteId ?? '')) : undefined;
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
  } = useForm<StreamRouteFormInput>({
    resolver: zodResolver(StreamRouteFormSchema),
    defaultValues: emptyFormValues,
  });

  const protocol = useWatch({ control, name: 'protocol' });
  const sniRestricted = useWatch({ control, name: 'sniRestricted' });

  const {
    data: existingRoute,
    error: routeError,
    isLoading: isLoadingRoute,
  } = useQuery({
    enabled: mode === 'edit' && Boolean(orgSlug && tenantSlug && routeId),
    queryFn: () => getTenantStreamRoute(orgSlug ?? '', tenantSlug, routeId ?? ''),
    queryKey: ['tenant-stream-route', orgSlug, tenantSlug, routeId],
  });

  useEffect(() => {
    if (!existingRoute) {
      return;
    }

    reset(toFormValues(existingRoute));
  }, [existingRoute, reset]);

  const routesPath = `${getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'routes',
    'routes',
  )}?${ROUTE_KIND_PARAM}=${STREAM_ROUTE_KIND}`;
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const leaveGuard = useUnsavedChangesGuard(isDirty);

  async function invalidateRoutes() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-stream-routes', orgSlug, tenantSlug],
    });

    if (orgSlug) {
      await invalidateAuditLogQueries(queryClient, orgSlug);
    }
  }

  const { isPending: isCreating, mutate: submitCreate } = useMutation({
    mutationFn: (payload: StreamRouteFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantStreamRoute(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.opened'), type: 'success' });
      await invalidateRoutes();
      router.push(routesPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.openFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdating, mutate: submitUpdate } = useMutation({
    mutationFn: (payload: StreamRouteFormInput) => {
      if (!orgSlug || !routeId) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantStreamRoute(orgSlug, tenantSlug, routeId, payload);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await invalidateRoutes();
      router.push(routesPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const isSubmitting = mode === 'create' ? isCreating : isUpdating;

  // Both fields below are hidden or disabled on a protocol that cannot carry
  // them, so a value left over from an earlier choice would be one the form
  // rejects and no longer offers any way to correct.
  function handleProtocolChange(next: StreamProtocol) {
    setValue('protocol', next, { shouldDirty: true, shouldValidate: true });

    if (!terminatesTls(next)) {
      setValue('policy', 'public', { shouldDirty: true, shouldValidate: true });
    }

    if (carriesSni(next)) {
      return;
    }

    setValue('sniRestricted', false, { shouldDirty: true });
    setValue('sniNames', [], { shouldDirty: true, shouldValidate: true });
  }

  function handleFormSubmit(payload: StreamRouteFormInput) {
    if (mode === 'create') {
      submitCreate(payload);
      return;
    }

    submitUpdate(payload);
  }

  const pageTitle = mode === 'create' ? t('newTitle') : t('editTitle');

  const headerTrail = isTenantView
    ? [{ href: routesPath, icon: 'route' }, { title: pageTitle }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: routesPath, title: navLabels.label('Routes') },
        { title: pageTitle },
      ];

  const routeErrorMessage = deriveErrorMessage([
    routeError,
    getApiErrorMessage(routeError, t('loadFailed')),
  ]);

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Routes"
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
                  onClick={() => leaveGuard.leaveTo(routesPath)}
                  className="w-auto border-borderGray bg-cardBg px-4 py-1.5 text-[14px] font-medium tracking-normal text-white hover:bg-hoverBg"
                >
                  {t('cancel')}
                </Button>
                <Button
                  type="button"
                  isLoading={isSubmitting}
                  disabled={!isDirty || (mode === 'edit' && isLoadingRoute)}
                  onClick={handleSubmit(handleFormSubmit)}
                  className="w-auto bg-focus px-4 py-1.5 text-[14px] font-medium tracking-normal text-white hover:bg-hoverBgPurple"
                >
                  {mode === 'create' ? t('open') : t('save')}
                </Button>
              </div>
            </div>

            <div className="p-4">
              {mode === 'edit' && isLoadingRoute ? (
                <p className="py-10 text-center text-xs font-medium text-textGray">
                  {t('loading')}
                </p>
              ) : mode === 'edit' && routeErrorMessage ? (
                <p className="py-10 text-center text-xs font-medium text-error">
                  {routeErrorMessage}
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
                      label={t('listenPort')}
                      placeholder="15432"
                      type="number"
                      hint={mode === 'edit' ? t('listenPortFixed') : t('listenPortClaimed')}
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('listenPort')}
                      error={errors.listenPort}
                      disabled={isSubmitting || mode === 'edit'}
                    />
                  </div>

                  <Controller
                    control={control}
                    name="protocol"
                    render={({ field }) => (
                      <Select
                        label={t('protocol')}
                        placeholder={t('protocolPlaceholder')}
                        hint={protocolHint(field.value)}
                        containerClassName={fieldContainerClassName}
                        className={fieldClassName}
                        options={protocolOptions}
                        value={field.value}
                        error={errors.protocol}
                        disabled={isSubmitting || mode === 'edit'}
                        onChange={(value) => handleProtocolChange(value as StreamProtocol)}
                      />
                    )}
                  />

                  <Controller
                    control={control}
                    name="policy"
                    render={({ field }) => (
                      <Select
                        label={t('access')}
                        placeholder={t('accessPlaceholder')}
                        hint={terminatesTls(protocol) ? t('accessHintTls') : t('accessHintPublic')}
                        containerClassName={fieldContainerClassName}
                        className={fieldClassName}
                        options={policyOptions}
                        value={field.value}
                        error={errors.policy}
                        disabled={isSubmitting || !terminatesTls(protocol)}
                        onChange={field.onChange}
                      />
                    )}
                  />

                  <StreamBackendsField
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    setValue={setValue}
                  />

                  {carriesSni(protocol) ? (
                    <div className="flex flex-col gap-3">
                      <Checkbox
                        label={t('sniRestricted')}
                        {...register('sniRestricted')}
                        disabled={isSubmitting}
                      />
                      {sniRestricted ? (
                        <StreamSniField
                          control={control}
                          errors={errors}
                          isSubmitting={isSubmitting}
                          setValue={setValue}
                        />
                      ) : null}
                    </div>
                  ) : null}

                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <Input
                      label={t('connectTimeout')}
                      type="number"
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('connectSecs')}
                      error={errors.connectSecs}
                      disabled={isSubmitting}
                    />
                    <Input
                      label={t('idleTimeout')}
                      type="number"
                      hint={t('idleTimeoutHint')}
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('idleSecs')}
                      error={errors.idleSecs}
                      disabled={isSubmitting}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
      <UnsavedChangesModal guard={leaveGuard} />
    </div>
  );
}
