import { getLocale, getTranslations } from 'next-intl/server';

import { PricingPlansGrid } from '@/components/landing/pricing/pricing-plans-grid';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { getPricingPlans } from '@/lib/api';

export async function PricingSection() {
  const t = await getTranslations('landing.pricing');
  const locale = await getLocale();
  const plans = await getPricingPlans(t, locale);

  return (
    <section id="pricing" className="px-6 py-16 text-center sm:py-24">
      <div className="mx-auto max-w-7xl">
        <ScrollReveal className="flex flex-col items-center">
          <SectionBadge
            className="mx-auto border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="mt-6 font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>

          <p className="mx-auto mt-6 max-w-2xl text-lg text-textGray sm:mt-8">{t('description')}</p>
        </ScrollReveal>

        <PricingPlansGrid plans={plans} />
      </div>
    </section>
  );
}
