import { useTranslations } from 'next-intl';

import { CLOUD_PROVIDER_OPTIONS, DEPLOYMENT_REGIONS, RESIDENCY_KIND_IDS } from '@/constants/cloud';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SelectOption } from '@/types/dashboard';
import type { IsolationLevelId, ResidencyKind } from '@/types/cloud-account';

/** The cloud and data-residency choices, worded in the current language. */
export function useCloudOptions() {
  const t = useTranslations('dashboard.cloud');
  const tJurisdictions = useLooseTranslations('dashboard.cloud.jurisdictions');

  const residencyKindOptions: SelectOption[] = RESIDENCY_KIND_IDS.map((id) => ({
    label: t(`residencyKinds.${id}`),
    value: id,
  }));
  // Region names follow the providers' own English naming; only the country is translated.
  const regionOptions: SelectOption[] = DEPLOYMENT_REGIONS.map((region) => ({
    label: `${region.label} — ${
      tJurisdictions.has(region.jurisdiction)
        ? tJurisdictions(region.jurisdiction)
        : region.jurisdiction
    }`,
    value: region.id,
  }));

  return {
    cloudProviderOptions: CLOUD_PROVIDER_OPTIONS,
    isolationLabel: (id: IsolationLevelId) => t(`isolation.${id}`),
    regionOptions,
    residencyKindHint: (kind: ResidencyKind) => t(`residencyHints.${kind}`),
    residencyKindOptions,
  };
}
