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
import { CustomPermissionsField } from '@/components/dashboard/tenant-detail/sections/routes/custom-permissions-field';
import { HostsField } from '@/components/dashboard/tenant-detail/sections/routes/hosts-field';
import { PathRewriteFields } from '@/components/dashboard/tenant-detail/sections/routes/path-rewrite-fields';
import { PipelineField } from '@/components/dashboard/tenant-detail/sections/routes/pipeline-field';
import { ScopesField } from '@/components/dashboard/tenant-detail/sections/routes/scopes-field';
import { ServiceField } from '@/components/dashboard/tenant-detail/sections/routes/service-field';
import { SystemPermissionsField } from '@/components/dashboard/tenant-detail/sections/routes/system-permissions-field';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import { useNotification } from '@/components/ui/notifications';
import { ROUTE_HTTP_METHOD_OPTIONS } from '@/constants/route';
import { useRouteOptions } from '@/hooks/dashboard/use-route-options';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useUnsavedChangesGuard } from '@/hooks/dashboard/use-unsaved-changes-guard';
import {
  createTenantRoute,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantRoute,
  updateTenantRoute,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { RouteFormSchema, type RouteFormInput } from '@/schemas/route-schemas';
import type { Route } from '@/types/route';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import {
  getRoutePolicyCustomPermissions,
  getRoutePolicyKind,
  getRoutePolicyScopes,
  getRoutePolicySystemPermissions,
} from '@/utils/route';

const emptyFormValues: RouteFormInput = {
  customPermissions: [],
  hostScope: 'All',
  hosts: [],
  methods: [],
  name: '',
  pathPattern: '',
  pathRewriteMode: 'strip_prefix',
  pathRewriteTemplate: '',
  pipelineId: '',
  policyKind: 'Authenticated',
  priority: '0',
  scopes: [],
  serviceId: '',
  systemPermissions: [],
};

function toFormValues(route: Route): RouteFormInput {
  return {
    customPermissions: getRoutePolicyCustomPermissions(route.policy),
    hostScope: route.hosts.length > 0 ? ('Specific' as const) : ('All' as const),
    hosts: route.hosts,
    methods: route.methods,
    name: route.name,
    pathPattern: route.pathPattern,
    pathRewriteMode: route.pathRewrite.mode,
    pathRewriteTemplate: route.pathRewrite.mode === 'template' ? route.pathRewrite.template : '',
    pipelineId: route.pipelineId,
    policyKind: getRoutePolicyKind(route.policy),
    priority: String(route.priority),
    scopes: getRoutePolicyScopes(route.policy),
    serviceId: route.serviceId,
    systemPermissions: getRoutePolicySystemPermissions(route.policy),
  };
}

type RouteFormPageProps = {
  mode: 'create' | 'edit';
};

export function RouteFormPage({ mode }: RouteFormPageProps) {
  const t = useTranslations('dashboard.routes.form');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const { policyKindOptions } = useRouteOptions();
  const router = useRouter();
  const params = useParams();
  const routeId = mode === 'edit' ? decodeURIComponent(String(params.routeId ?? '')) : undefined;
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
  } = useForm<RouteFormInput>({
    resolver: zodResolver(RouteFormSchema),
    defaultValues: emptyFormValues,
  });

  const {
    data: existingRoute,
    error: routeError,
    isLoading: isLoadingRoute,
  } = useQuery({
    enabled: mode === 'edit' && Boolean(orgSlug && tenantSlug && routeId),
    queryFn: () => getTenantRoute(orgSlug ?? '', tenantSlug, routeId ?? ''),
    queryKey: ['tenant-route', orgSlug, tenantSlug, routeId],
  });

  useEffect(() => {
    if (!existingRoute) {
      return;
    }

    reset(toFormValues(existingRoute));
  }, [existingRoute, reset]);

  const policyKind = useWatch({ control, name: 'policyKind' });

  const routesPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'routes', 'routes');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const leaveGuard = useUnsavedChangesGuard(isDirty);

  async function invalidateRoutes() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-routes', orgSlug, tenantSlug] });

    if (orgSlug) {
      await invalidateAuditLogQueries(queryClient, orgSlug);
    }
  }

  const { isPending: isCreating, mutate: submitCreateRoute } = useMutation({
    mutationFn: (payload: RouteFormInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createTenantRoute(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.created'), type: 'success' });
      await invalidateRoutes();
      router.push(routesPath);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isUpdating, mutate: submitUpdateRoute } = useMutation({
    mutationFn: (payload: RouteFormInput) => {
      if (!orgSlug || !routeId) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantRoute(orgSlug, tenantSlug, routeId, payload);
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

  function handleFormSubmit(payload: RouteFormInput) {
    if (mode === 'create') {
      submitCreateRoute(payload);
      return;
    }

    submitUpdateRoute(payload);
  }

  const pageTitle = mode === 'create' ? t('newTitle') : t('editTitle');
  const headerCrumbTitle = mode === 'create' ? t('createCrumb') : t('editTitle');

  const headerTrail = isTenantView
    ? [{ href: routesPath, icon: 'route' }, { title: headerCrumbTitle }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: routesPath, title: navLabels.label('Routes') },
        { title: headerCrumbTitle },
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
                  className="w-auto border-borderGray bg-cardBg px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
                >
                  {t('cancel')}
                </Button>
                <Button
                  type="button"
                  isLoading={isSubmitting}
                  disabled={!isDirty || (mode === 'edit' && isLoadingRoute)}
                  onClick={handleSubmit(handleFormSubmit)}
                  className="w-auto bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple"
                >
                  {mode === 'create' ? t('add') : t('save')}
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
                      label={t('priority')}
                      placeholder="100"
                      containerClassName={fieldContainerClassName}
                      className={fieldClassName}
                      {...register('priority')}
                      error={errors.priority}
                      disabled={isSubmitting}
                    />
                  </div>

                  <Input
                    label={t('pathPattern')}
                    placeholder="/api/users/*"
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    {...register('pathPattern')}
                    error={errors.pathPattern}
                    disabled={isSubmitting}
                  />

                  <HostsField
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    orgSlug={orgSlug}
                    setValue={setValue}
                    tenantSlug={tenantSlug}
                  />

                  <PipelineField
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    orgSlug={orgSlug}
                    setValue={setValue}
                    tenantSlug={tenantSlug}
                  />

                  <Controller
                    control={control}
                    name="methods"
                    render={({ field }) => (
                      <MultiSelect
                        label={t('methods')}
                        placeholder={t('methodsPlaceholder')}
                        containerClassName={fieldContainerClassName}
                        className={fieldClassName}
                        options={ROUTE_HTTP_METHOD_OPTIONS}
                        value={field.value}
                        error={errors.methods?.message}
                        onChange={field.onChange}
                      />
                    )}
                  />

                  <ServiceField
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    orgSlug={orgSlug}
                    setValue={setValue}
                    tenantSlug={tenantSlug}
                  />

                  <PathRewriteFields
                    control={control}
                    errors={errors}
                    isSubmitting={isSubmitting}
                    register={register}
                  />

                  <Controller
                    control={control}
                    name="policyKind"
                    render={({ field }) => (
                      <Select
                        label={t('policy')}
                        placeholder={t('policyPlaceholder')}
                        containerClassName={fieldContainerClassName}
                        className={fieldClassName}
                        options={policyKindOptions}
                        value={field.value}
                        error={errors.policyKind}
                        onChange={field.onChange}
                      />
                    )}
                  />

                  {policyKind === 'RequireSystemPermission' ? (
                    <SystemPermissionsField
                      control={control}
                      errors={errors}
                      isSubmitting={isSubmitting}
                      open
                      orgSlug={orgSlug}
                      setValue={setValue}
                      tenantSlug={tenantSlug}
                    />
                  ) : null}

                  {policyKind === 'RequireCustomPermission' ? (
                    <CustomPermissionsField
                      control={control}
                      errors={errors}
                      isSubmitting={isSubmitting}
                      setValue={setValue}
                    />
                  ) : null}

                  {policyKind === 'RequireScope' ? (
                    <ScopesField
                      control={control}
                      errors={errors}
                      isSubmitting={isSubmitting}
                      setValue={setValue}
                    />
                  ) : null}
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
