'use client';

import { useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { useNotification } from '@/components/ui/notifications';
import { DEFAULT_SIGN_IN_PREFIX, SIGN_IN_ADDRESS_KEYS } from '@/constants/service';
import { useServiceOptions } from '@/hooks/dashboard/use-service-options';
import {
  getApiErrorMessage,
  getTenantDomains,
  getTenantServices,
  updateServiceAppSignIn,
} from '@/lib/api';
import { AppSignInFormSchema, type AppSignInFormInput } from '@/schemas/app-sign-in-schemas';
import type { GatewayService } from '@/types/gateway-service';

const NO_SERVICE = '';

type AppSignInCardProps = {
  orgSlug: string;
  service: GatewayService;
  tenantSlug: string;
};

function toFormValues(service: GatewayService): AppSignInFormInput {
  const signIn = service.appSignIn;
  const delivery = service.signInDelivery;

  return {
    acceptsAppSignInOf: service.acceptsAppSignInOf ?? NO_SERVICE,
    afterSignIn: signIn?.afterSignIn ?? '/',
    cookieHosts: delivery?.kind === 'own_cookie' ? delivery.hosts : [],
    deliveryKind: delivery?.kind ?? 'same_host',
    enabled: Boolean(signIn),
    hosts: signIn?.hosts ?? [],
    paths: {
      login: signIn?.paths.login ?? '',
      logout: signIn?.paths.logout ?? '',
      mfa: signIn?.paths.mfa ?? '',
      signup: signIn?.paths.signup ?? '',
      verify: signIn?.paths.verify ?? '',
    },
    prefix: signIn?.prefix ?? DEFAULT_SIGN_IN_PREFIX,
    signedOutBrowsers: signIn?.signedOutBrowsers ?? 'refuse',
  };
}

export function AppSignInCard({ orgSlug, service, tenantSlug }: AppSignInCardProps) {
  const t = useTranslations('dashboard.services.appSignIn');
  const { signInAddressLabel, signInDeliveryHint, signInDeliveryOptions, signedOutBrowserOptions } =
    useServiceOptions();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();

  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<AppSignInFormInput>({
    resolver: zodResolver(AppSignInFormSchema),
    defaultValues: toFormValues(service),
  });

  useEffect(() => {
    reset(toFormValues(service));
  }, [service, reset]);

  const enabled = useWatch({ control, name: 'enabled' });
  const acceptsAppSignInOf = useWatch({ control, name: 'acceptsAppSignInOf' });
  const deliveryKind = useWatch({ control, name: 'deliveryKind' });
  const prefix = useWatch({ control, name: 'prefix' }) || DEFAULT_SIGN_IN_PREFIX;

  const { data: domains } = useQuery({
    queryFn: () => getTenantDomains(orgSlug, tenantSlug, { limit: 100 }),
    queryKey: ['tenant-domains', orgSlug, tenantSlug, 'app-sign-in'],
  });
  const { data: services } = useQuery({
    queryFn: () => getTenantServices(orgSlug, tenantSlug, { limit: 100 }),
    queryKey: ['tenant-services', orgSlug, tenantSlug, 'app-sign-in'],
  });

  const hostOptions = (domains?.items ?? [])
    .filter((domain) => domain.verificationStatus === 'Verified')
    .map((domain) => ({ label: domain.domain, value: domain.domain }));
  const ownerOptions = [
    { label: t('none'), value: NO_SERVICE },
    ...(services?.items ?? [])
      .filter((other) => other.id !== service.id && other.appSignIn)
      .map((other) => ({ label: other.name, value: other.id })),
  ];

  const { isPending, mutate: save } = useMutation({
    mutationFn: (payload: AppSignInFormInput) =>
      updateServiceAppSignIn(orgSlug, tenantSlug, service.id, payload),
    onSuccess: async () => {
      showNotification({ message: t('saved'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-service', orgSlug, tenantSlug, service.id],
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-services', orgSlug, tenantSlug] });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('saveFailed')),
        type: 'error',
      });
    },
  });

  const needsAudience = !service.expectedAudience;

  return (
    <div className="mx-auto mt-4 w-full max-w-360 overflow-hidden rounded-lg border border-borderGray bg-cardBg">
      <div className="flex flex-col gap-4 border-b border-borderGray p-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-base font-bold text-white">{t('title')}</h2>
          <p className="mt-1 text-xs text-textGray">{t('description')}</p>
        </div>
        <Button
          type="button"
          isLoading={isPending}
          disabled={!isDirty}
          onClick={handleSubmit((payload) => save(payload))}
          className="w-auto shrink-0 bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple"
        >
          {t('save')}
        </Button>
      </div>

      <div className="flex flex-col gap-4 p-4">
        <Controller
          control={control}
          name="enabled"
          render={({ field }) => (
            <Switch
              checked={field.value}
              disabled={isPending || needsAudience}
              label={t('enable')}
              description={needsAudience ? t('needsAudience') : t('enableHint')}
              onCheckedChange={field.onChange}
            />
          )}
        />

        {enabled ? (
          <>
            <Controller
              control={control}
              name="hosts"
              render={({ field }) => (
                <MultiSelect
                  label={t('domains')}
                  placeholder={t('domainsPlaceholder')}
                  hint={t('domainsHint')}
                  options={hostOptions}
                  value={field.value}
                  error={errors.hosts?.message}
                  disabled={isPending}
                  onChange={field.onChange}
                />
              )}
            />

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Input
                label={t('prefix')}
                placeholder={DEFAULT_SIGN_IN_PREFIX}
                hint={t('prefixHint')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('prefix')}
                error={errors.prefix}
                disabled={isPending}
              />
              <Input
                label={t('afterSignIn')}
                placeholder="/"
                hint={t('afterSignInHint')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('afterSignIn')}
                error={errors.afterSignIn}
                disabled={isPending}
              />
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {SIGN_IN_ADDRESS_KEYS.map((key) => (
                <Input
                  key={key}
                  label={signInAddressLabel(key)}
                  placeholder={`${prefix}/${key}`}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  {...register(`paths.${key}`)}
                  error={errors.paths?.[key]}
                  disabled={isPending}
                />
              ))}
            </div>

            <Controller
              control={control}
              name="signedOutBrowsers"
              render={({ field }) => (
                <Select
                  label={t('signedOutLabel')}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={signedOutBrowserOptions}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />
          </>
        ) : (
          <>
            <Controller
              control={control}
              name="acceptsAppSignInOf"
              render={({ field }) => (
                <Select
                  label={t('acceptsOf')}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={ownerOptions}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />

            {acceptsAppSignInOf ? (
              <Controller
                control={control}
                name="deliveryKind"
                render={({ field }) => (
                  <Select
                    label={t('deliveryLabel')}
                    hint={signInDeliveryHint(deliveryKind)}
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    options={signInDeliveryOptions}
                    value={field.value}
                    disabled={isPending}
                    onChange={field.onChange}
                  />
                )}
              />
            ) : null}

            {acceptsAppSignInOf && deliveryKind === 'own_cookie' ? (
              <Controller
                control={control}
                name="cookieHosts"
                render={({ field }) => (
                  <MultiSelect
                    label={t('cookieDomains')}
                    placeholder={t('domainsPlaceholder')}
                    hint={t('domainsHint')}
                    options={hostOptions}
                    value={field.value}
                    error={errors.cookieHosts?.message}
                    disabled={isPending}
                    onChange={field.onChange}
                  />
                )}
              />
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}
