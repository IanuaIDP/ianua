import Image from 'next/image';
import { useTranslations } from 'next-intl';

import useCasesDiagram from '@/assets/use-cases-diagram.svg';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { USE_CASES } from '@/constants/landing';
import { cn } from '@/utils/cn';

export function UseCasesSection() {
  const t = useTranslations('landing.useCases');

  return (
    <section id="use-cases" className="px-6 pt-16 sm:pt-24">
      <div className="mx-auto max-w-7xl">
        <ScrollReveal className="flex flex-col items-center text-center">
          <SectionBadge
            className="mx-auto border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="mx-auto mt-6 max-w-4xl font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>
        </ScrollReveal>

        <div className="mt-8 grid grid-cols-1 items-center gap-8 sm:mt-12 sm:gap-12 lg:grid-cols-[40%_60%]">
          <ScrollReveal className="flex justify-center" delayMs={120}>
            <Image src={useCasesDiagram} alt="" className="h-auto w-full max-w-sm object-contain" />
          </ScrollReveal>

          <ScrollReveal delayMs={180}>
            <div>
              {USE_CASES.map((useCase, index) => (
                <article
                  key={useCase.id}
                  className={cn(
                    'py-6 sm:py-8',
                    index === 0 && 'pt-0!',
                    index === USE_CASES.length - 1 && 'pb-0!',
                    index !== USE_CASES.length - 1 && 'border-b border-borderGray',
                  )}
                >
                  <h3 className="font-['Space_Grotesk','Manrope',sans-serif] text-2xl font-bold text-white">
                    {t(`items.${useCase.id}.title`)}
                  </h3>
                  <p className="mt-4 text-lg text-textGray">
                    {t(`items.${useCase.id}.description`)}
                  </p>
                </article>
              ))}
            </div>
          </ScrollReveal>
        </div>
      </div>
    </section>
  );
}
