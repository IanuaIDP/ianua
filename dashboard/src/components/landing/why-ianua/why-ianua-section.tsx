import { useTranslations } from 'next-intl';

import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { ReasonCard } from './reason-card';
import { WHY_IANUA_REASONS } from '@/constants/landing';

export function WhyIanuaSection() {
  const t = useTranslations('landing.whyIanua');

  return (
    <section id="why-Ianua" className="px-6 pt-16 pb-10 sm:pt-24 sm:pb-12">
      <div className="mx-auto max-w-7xl">
        <ScrollReveal className="flex flex-col items-center text-center">
          <SectionBadge
            className="mx-auto border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="mt-6 max-w-4xl font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold text-white sm:mt-8 sm:text-4xl lg:text-[56px]">
            {t.rich('title', {
              block: (chunks) => <span className="block">{chunks}</span>,
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>
        </ScrollReveal>

        <ScrollReveal
          className="mt-10 grid grid-cols-1 gap-8 sm:mt-16 sm:grid-cols-2 sm:gap-12 lg:grid-cols-5 lg:gap-12"
          delayMs={140}
        >
          {WHY_IANUA_REASONS.map((reason) => (
            <ReasonCard
              key={reason.number}
              number={reason.number}
              title={t(`reasons.${reason.id}.title`)}
              description={t(`reasons.${reason.id}.description`)}
            />
          ))}
        </ScrollReveal>
      </div>
    </section>
  );
}
