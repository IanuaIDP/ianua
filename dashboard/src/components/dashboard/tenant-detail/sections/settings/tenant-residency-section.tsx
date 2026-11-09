'use client';

import { useQuery } from '@tanstack/react-query';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { getCloudProviderLabel, getRegionLabel } from '@/constants/cloud';
import { useCloudOptions } from '@/hooks/dashboard/use-cloud-options';
import { useLooseTranslations, type LooseTranslator } from '@/hooks/i18n/use-loose-translations';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, getTenant } from '@/lib/api';
import type { TenantResidency } from '@/types/cloud-account';

type ResidencyFact = {
  label: string;
  value: string;
};

function getResidencyFacts(
  residency: TenantResidency,
  options: ReturnType<typeof useCloudOptions>,
  t: LooseTranslator,
): ResidencyFact[] {
  const kindLabel =
    options.residencyKindOptions.find((option) => option.value === residency.kind)?.label ??
    residency.kind;
  const facts: ResidencyFact[] = [
    { label: t('hosting'), value: kindLabel },
    { label: t('isolation'), value: options.isolationLabel(residency.isolation) },
  ];

  if (residency.provider) {
    facts.push({ label: t('cloud'), value: getCloudProviderLabel(residency.provider) });
  }

  if (residency.region) {
    facts.push({ label: t('region'), value: getRegionLabel(residency.region) });
  }

  if (residency.dataResidency) {
    facts.push({ label: t('jurisdiction'), value: residency.dataResidency });
  }

  if (residency.kind === 'customer_cloud') {
    facts.push({
      label: t('network'),
      value: residency.networkPending
        ? t('networkPending')
        : (residency.network ?? t('notAvailable')),
    });
  }

  return facts;
}

export function TenantResidencySection() {
  const t = useLooseTranslations('dashboard.tenants.residencySection');
  const cloudOptions = useCloudOptions();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const {
    data: tenant,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenant(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-detail', orgSlug, tenantSlug],
  });

  return (
    <SettingsCard title={t('title')} description={t('description')}>
      {error ? (
        <p className="text-sm font-medium text-error">
          {getApiErrorMessage(error, t('loadFailed'))}
        </p>
      ) : isLoading || !tenant ? (
        <p className="text-xs font-medium text-textGray">{t('loading')}</p>
      ) : (
        <div className="flex flex-wrap divide-x divide-borderGray overflow-hidden rounded-[10px] border border-borderGray">
          {getResidencyFacts(tenant.residency, cloudOptions, t).map((fact) => (
            <div
              key={fact.label}
              className="flex min-w-35 flex-1 flex-col items-start justify-center gap-1.5 px-4 py-3"
            >
              <span className="text-xs text-textGray">{fact.label}</span>
              <span className="break-all text-xs text-white">{fact.value}</span>
            </div>
          ))}
        </div>
      )}
    </SettingsCard>
  );
}
