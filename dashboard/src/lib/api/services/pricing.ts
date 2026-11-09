import { API_URL } from '@/constants/api';
import { buildFallbackPricingPlans } from '@/constants/pricing';
import { DEFAULT_LOCALE } from '@/i18n/config';
import type { PricingPlan } from '@/types/landing';
import type { PlanCatalogResponse, PlanTierResponse, PricingTranslator } from '@/types/pricing';

// Plan names, taglines and badges come from the backend. In English they are
// shown as the backend sends them; in other languages a translation is used
// when messages/<language>.json has one for that plan, and the backend text
// otherwise. The typed translator cannot check keys built from backend values,
// so it is used through this looser view.
type LooseTranslator = {
  (key: string, values?: Record<string, number | string>): string;
  has: (key: string) => boolean;
};

function translateBackendText(
  t: LooseTranslator,
  locale: string,
  key: string,
  backendText: string,
): string {
  if (locale === DEFAULT_LOCALE || !t.has(key)) {
    return backendText;
  }

  return t(key);
}

function formatCount(value: number): string {
  if (value >= 1_000_000) {
    return `${Math.round(value / 1_000_000)}M`;
  }
  if (value >= 1_000) {
    return `${Math.round(value / 1_000)}K`;
  }
  return `${value}`;
}

function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat('en-US', {
    currency,
    maximumFractionDigits: 0,
    style: 'currency',
  }).format(cents / 100);
}

function mapPlanTierToPricingPlan(
  tier: PlanTierResponse,
  currency: string,
  translator: PricingTranslator,
  locale: string,
): PricingPlan {
  const t = translator as unknown as LooseTranslator;
  const { limits } = tier;
  const isNegotiated = tier.call_to_action === 'contact_sales';
  const isCustomTier = tier.plan === 'Custom';

  const features = isCustomTier
    ? []
    : [
        t('features.users', { count: formatCount(limits.max_users) }),
        t('features.tenants', { count: limits.max_tenants_per_org }),
        t('features.routes', { count: formatCount(limits.max_routes) }),
        t('features.proxyRequests', { count: formatCount(limits.max_proxy_requests_per_month) }),
        t('features.auditRetention', { days: limits.audit_retention_days }),
        t('features.isolation', {
          levels: limits.allowed_isolation.map((level) => t(`isolation.${level}`)).join(', '),
        }),
      ];

  const name = translateBackendText(t, locale, `tiers.${tier.plan}.name`, tier.display_name);
  const buttonLabel = isNegotiated
    ? t('buttons.contactSales')
    : tier.plan === 'Free'
      ? t('buttons.startForFree')
      : t('buttons.upgradeTo', { name });

  return {
    badge: tier.badge
      ? translateBackendText(
          t,
          locale,
          tier.badge === 'Most Popular' ? 'badges.mostPopular' : `badges.${tier.badge}`,
          tier.badge,
        )
      : undefined,
    buttonHref: isNegotiated ? '#contact' : '/sign-up',
    buttonLabel,
    buttonTone: isNegotiated ? 'focus' : undefined,
    features,
    hidePricePeriod: !tier.price,
    highlighted: tier.highlighted,
    listTitle: t.has(`tiers.${tier.plan}.listTitle`)
      ? t(`tiers.${tier.plan}.listTitle`)
      : tier.tagline,
    name,
    price: tier.price
      ? {
          annual: formatPrice(tier.price.annual_cents, currency),
          monthly: formatPrice(tier.price.monthly_cents, currency),
        }
      : { annual: t('customPrice'), monthly: t('customPrice') },
    subtitle: translateBackendText(t, locale, `tiers.${tier.plan}.tagline`, tier.tagline),
  };
}

/**
 * Fetches the live pricing catalog from the public, unauthenticated
 * `GET /plans` endpoint. Falls back to `buildFallbackPricingPlans` on any
 * failure — missing config, network error, non-2xx response, or an empty
 * plan list — so the pricing section can never render nothing.
 *
 * Fetched server-side only (this runs inside the `PricingSection` server
 * component) and cached for an hour via Next's fetch cache, since prices
 * change at most monthly.
 */
export async function getPricingPlans(
  translator: PricingTranslator,
  locale: string,
): Promise<PricingPlan[]> {
  const fallbackPlans = buildFallbackPricingPlans(translator);

  if (!API_URL) {
    return fallbackPlans;
  }

  try {
    const response = await fetch(`${API_URL}/plans`, {
      next: { revalidate: 3600 },
    });

    if (!response.ok) {
      return fallbackPlans;
    }

    const data = (await response.json()) as PlanCatalogResponse;

    if (!data.plans?.length) {
      return fallbackPlans;
    }

    return data.plans.map((tier) =>
      mapPlanTierToPricingPlan(tier, data.currency, translator, locale),
    );
  } catch {
    return fallbackPlans;
  }
}
