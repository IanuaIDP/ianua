import type { PricingTranslator } from '@/types/pricing';
import type { PricingPlan } from '@/types/landing';

/**
 * Plans shown when the live catalog cannot be loaded. The text comes from
 * messages/<language>.json (`landing.pricing`); limits are written here.
 */
export function buildFallbackPricingPlans(t: PricingTranslator): PricingPlan[] {
  return [
    {
      name: t('tiers.Free.name'),
      price: {
        monthly: '$0',
        annual: '$0',
      },
      subtitle: t('tiers.Free.tagline'),
      buttonLabel: t('fallback.Free.buttonLabel'),
      buttonHref: '/sign-up',
      footnote: t('fallback.Free.footnote'),
      listTitle: t('tiers.Free.listTitle'),
      features: [
        t('features.users', { count: '100' }),
        t('features.tenants', { count: 1 }),
        t('features.routes', { count: '3' }),
        t('features.proxyRequests', { count: '500k' }),
        t('features.auditRetention', { days: 30 }),
        t('features.isolation', {
          levels: [t('isolation.Shared'), t('isolation.DedicatedSchema')].join(', '),
        }),
      ],
    },
    {
      name: t('tiers.Starter.name'),
      badge: t('badges.mostPopular'),
      price: {
        monthly: '$29',
        annual: '$348',
      },
      subtitle: t('tiers.Starter.tagline'),
      buttonLabel: t('fallback.Starter.buttonLabel'),
      buttonHref: '/sign-up',
      footnote: t('fallback.Starter.footnote'),
      highlighted: true,
      listTitle: t('tiers.Starter.listTitle'),
      features: [
        t('features.users', { count: '10k' }),
        t('features.tenants', { count: 3 }),
        t('features.routes', { count: '25' }),
        t('features.proxyRequests', { count: '25M' }),
        t('features.auditRetention', { days: 90 }),
        t('features.isolation', {
          levels: [t('isolation.Shared'), t('isolation.DedicatedSchema')].join(', '),
        }),
      ],
    },
    {
      name: t('tiers.Business.name'),
      price: {
        monthly: '$149',
        annual: '$1,788',
      },
      subtitle: t('tiers.Business.tagline'),
      buttonLabel: t('fallback.Business.buttonLabel'),
      buttonHref: '/sign-up',
      buttonTone: 'focus',
      footnote: t('fallback.Business.footnote'),
      listTitle: t('fallback.Business.listTitle'),
      features: [
        t('features.users', { count: '100k' }),
        t('features.tenants', { count: 25 }),
        t('features.routes', { count: '250' }),
        t('features.proxyRequests', { count: '500M' }),
        t('features.auditRetention', { days: 365 }),
        t('features.isolation', {
          levels: [
            t('isolation.Shared'),
            t('isolation.DedicatedSchema'),
            t('isolation.DedicatedInstance'),
            t('isolation.DedicatedCluster'),
          ].join(', '),
        }),
      ],
    },
    {
      name: t('tiers.Custom.name'),
      isCustom: true,
      heading: t('fallback.Custom.heading'),
      price: {
        monthly: t('customPrice'),
        annual: t('customPrice'),
      },
      hidePricePeriod: true,
      subtitle: t('tiers.Custom.tagline'),
      buttonLabel: t('fallback.Custom.buttonLabel'),
      buttonHref: '#contact',
      buttonTone: 'focus',
      footnote: t('fallback.Custom.footnote'),
      listTitle: t('fallback.Custom.listTitle'),
      requirementsDescription: t('fallback.Custom.requirements'),
      features: [],
    },
  ];
}
