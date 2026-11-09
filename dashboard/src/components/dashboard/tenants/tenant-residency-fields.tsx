'use client';

import { useQuery } from '@tanstack/react-query';
import { Controller, useFormContext, useWatch } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Select } from '@/components/ui/Select';
import { getCloudProvider, getRegionSlug } from '@/constants/cloud';
import { useCloudOptions } from '@/hooks/dashboard/use-cloud-options';
import { useFieldError } from '@/hooks/i18n/use-field-error';
import { getApiErrorMessage, getCloudNetworks } from '@/lib/api';
import type { CreateTenantInput } from '@/schemas/tenant-schemas';
import type { CloudProviderId, DeploymentRegionId, ResidencyKind } from '@/types/cloud-account';

type TenantResidencyFieldsProps = {
  connectedProviders: CloudProviderId[];
  disabled?: boolean;
  orgSlug?: string;
};

const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';
const buildNetworkValue = '';

export function TenantResidencyFields({
  connectedProviders,
  disabled = false,
  orgSlug,
}: TenantResidencyFieldsProps) {
  const t = useTranslations('dashboard.tenants.residency');
  const { cloudProviderOptions, regionOptions, residencyKindHint, residencyKindOptions } =
    useCloudOptions();
  const {
    control,
    formState: { errors },
  } = useFormContext<CreateTenantInput>();
  const kind = (useWatch({ control, name: 'residency.kind' }) ?? 'platform') as ResidencyKind;
  const provider = useWatch({ control, name: 'residency.provider' }) as CloudProviderId | undefined;
  const region = useWatch({ control, name: 'residency.region' }) as DeploymentRegionId | undefined;
  const residencyErrors = errors.residency;
  const isolationError = useFieldError(residencyErrors?.isolation?.message);

  const isCustomerCloud = kind === 'customer_cloud';
  const isProviderConnected = Boolean(provider && connectedProviders.includes(provider));

  const {
    data: networks = [],
    error: networksError,
    isLoading: isLoadingNetworks,
  } = useQuery({
    enabled: isCustomerCloud && isProviderConnected && Boolean(orgSlug && provider && region),
    queryFn: () => getCloudNetworks(orgSlug ?? '', provider ?? 'aws', getRegionSlug(region!)),
    queryKey: ['cloud-networks', orgSlug, provider, region],
  });

  const providerMeta = provider ? getCloudProvider(provider) : undefined;
  const canBuildNetwork = providerMeta?.buildsNetworks ?? true;
  const networkKind = canBuildNetwork ? 'network' : 'namespace';
  const networkLabel = t(`${networkKind}.label`);

  const networkOptions = [
    ...(canBuildNetwork ? [{ label: t('buildNetwork'), value: buildNetworkValue }] : []),
    ...networks.map((network) => ({
      label: `${network.name} (${network.handle})`,
      value: network.handle,
    })),
  ];

  function networkHint() {
    if (networksError) {
      return getApiErrorMessage(networksError, t(`${networkKind}.listFailed`));
    }

    if (networks.length === 0 && region && !isLoadingNetworks) {
      return t(`${networkKind}.noneFound`);
    }

    return t(`${networkKind}.hint`);
  }

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-borderGray px-4 py-4">
      <Controller
        control={control}
        name="residency.kind"
        render={({ field }) => (
          <Select
            label={t('kind')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            disabled={disabled}
            hint={residencyKindHint(kind)}
            options={residencyKindOptions}
            value={field.value}
            onChange={field.onChange}
          />
        )}
      />

      {isCustomerCloud ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Controller
            control={control}
            name="residency.provider"
            render={({ field }) => (
              <Select
                label={t('cloud')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                disabled={disabled}
                error={residencyErrors?.provider?.message}
                options={cloudProviderOptions}
                placeholder={t('cloudPlaceholder')}
                value={field.value ?? ''}
                onChange={field.onChange}
              />
            )}
          />
          <Controller
            control={control}
            name="residency.region"
            render={({ field }) => (
              <Select
                label={t('region')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                disabled={disabled}
                error={residencyErrors?.region?.message}
                hint={canBuildNetwork ? undefined : t('regionHint')}
                options={regionOptions}
                placeholder={t('regionPlaceholder')}
                value={field.value ?? ''}
                onChange={field.onChange}
              />
            )}
          />
        </div>
      ) : null}

      {isCustomerCloud && provider && !isProviderConnected ? (
        <p className="text-xs font-medium text-orange">{t('notConnected')}</p>
      ) : null}

      {isCustomerCloud && isProviderConnected ? (
        <Controller
          control={control}
          name="residency.network"
          render={({ field }) => (
            <Select
              label={networkLabel}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              disabled={disabled || isLoadingNetworks || !region}
              hint={networkHint()}
              options={networkOptions}
              placeholder={canBuildNetwork ? undefined : t('namespace.placeholder')}
              value={field.value ?? buildNetworkValue}
              onChange={field.onChange}
            />
          )}
        />
      ) : null}

      {isolationError ? <p className="text-xs font-medium text-error">{isolationError}</p> : null}
    </div>
  );
}
