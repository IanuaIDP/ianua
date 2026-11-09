import { useTranslations } from 'next-intl';

import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';

export function ProblemSection() {
  const t = useTranslations('landing.problem');

  return (
    <section id="problem" className="bg-appBg px-6 pt-12 pb-16 text-white sm:pb-24 md:px-30">
      <div className="mx-auto grid max-w-7xl grid-cols-1 gap-8 sm:gap-18.75 lg:grid-cols-2">
        <ScrollReveal>
          <SectionBadge>{t('badge')}</SectionBadge>

          <h2 className="mt-6 max-w-130 font-['Space_Grotesk','Manrope',sans-serif] text-[36px] font-bold leading-11 text-white sm:mt-8 sm:text-5xl sm:leading-14 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>
        </ScrollReveal>

        <ScrollReveal className="flex flex-col justify-start" delayMs={140}>
          <p className="max-w-150 text-lg leading-7 font-normal text-textGray">{t('body')}</p>

          <p className="mt-6 max-w-140 border-l-2 border-primary pl-8 text-2xl sm:mt-8 sm:text-[32px] font-bold leading-10 font-['Space_Grotesk','Manrope',sans-serif] text-white">
            {t('closing')}
          </p>
        </ScrollReveal>
      </div>
    </section>
  );
}
