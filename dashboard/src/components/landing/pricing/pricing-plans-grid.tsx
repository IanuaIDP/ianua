'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { PricingCard, type PricingPlan } from '@/components/landing/pricing/pricing-card';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { cn } from '@/utils/cn';

type BillingPeriod = 'monthly' | 'annual';

type PricingPlansGridProps = {
  plans: PricingPlan[];
};

export function PricingPlansGrid({ plans }: PricingPlansGridProps) {
  const t = useTranslations('landing.pricing');
  const [billingPeriod, setBillingPeriod] = useState<BillingPeriod>('monthly');

  return (
    <ScrollReveal className="flex flex-col items-center" delayMs={140}>
      <div className="mt-6 inline-flex rounded-lg bg-cardBg p-1 text-xs sm:mt-8">
        <button
          type="button"
          className={cn(
            'rounded-md px-3 py-1 font-medium transition-colors duration-200',
            billingPeriod === 'monthly'
              ? 'bg-primary/10 text-primary'
              : 'text-textGray hover:text-white',
          )}
          aria-pressed={billingPeriod === 'monthly'}
          onClick={() => setBillingPeriod('monthly')}
        >
          {t('monthly')}
        </button>
        <button
          type="button"
          className={cn(
            'flex items-center gap-1.5 rounded-md px-3 py-1 font-medium transition-colors duration-200',
            billingPeriod === 'annual'
              ? 'bg-primary/10 text-primary'
              : 'text-textGray hover:text-white',
          )}
          aria-pressed={billingPeriod === 'annual'}
          onClick={() => setBillingPeriod('annual')}
        >
          {t('annually')}
          <span className="rounded-full bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
            {t('annualDiscount')}
          </span>
        </button>
      </div>

      <div className="mt-6 grid w-full grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {plans.map((plan) => (
          <PricingCard key={plan.name} billingPeriod={billingPeriod} plan={plan} />
        ))}
      </div>
    </ScrollReveal>
  );
}
