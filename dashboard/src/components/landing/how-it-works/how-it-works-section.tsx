import Image from 'next/image';
import { useTranslations } from 'next-intl';

import howItWorksScreenshot from '@/assets/how-it-works-screenshot.svg';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { LandingHorizontalScrollContainer } from '@/components/landing/shared/landing-horizontal-scroll-container';
import { HOW_IT_WORKS_STEPS, PER_REQUEST_CHECK_GROUPS } from '@/constants/landing';
import { StepCard } from './step-card';

export function HowItWorksSection() {
  const t = useTranslations('landing.howItWorks');

  return (
    <section id="how-it-works" className="px-6 pt-16 pb-10 sm:pt-24 sm:pb-12">
      <div className="mx-auto flex max-w-7xl flex-col items-center text-center">
        <ScrollReveal className="flex flex-col items-center">
          <SectionBadge className="mx-auto border-borderGray bg-cardBg px-4 py-2">
            {t('badge')}
          </SectionBadge>

          <h2 className="mt-6 max-w-7xl text-3xl font-bold text-white sm:mt-8 sm:text-4xl lg:text-[56px] font-['Space_Grotesk','Manrope',sans-serif]">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>

          <p className="mt-6 text-lg text-textGray sm:mt-8">
            {t.rich('intro', {
              brand: (chunks) => <span className="text-focus">{chunks}</span>,
            })}
          </p>
        </ScrollReveal>

        <ScrollReveal
          className="mt-6 w-full overflow-hidden rounded-2xl border border-borderGray bg-cardBg sm:mt-8"
          delayMs={120}
        >
          <LandingHorizontalScrollContainer className="lg:grid lg:grid-cols-7 lg:overflow-visible">
            {HOW_IT_WORKS_STEPS.map((step, index) => (
              <StepCard
                key={step.number}
                number={step.number}
                title={t(`steps.${step.id}.title`)}
                description={t(`steps.${step.id}.description`)}
                isLast={index === HOW_IT_WORKS_STEPS.length - 1}
              />
            ))}
          </LandingHorizontalScrollContainer>
        </ScrollReveal>

        <ScrollReveal className="mt-10 flex w-full justify-center sm:mt-14" delayMs={200}>
          <Image
            src={howItWorksScreenshot}
            alt={t('screenshotAlt')}
            className="h-auto w-full max-w-sm object-contain sm:max-w-lg md:max-w-3xl lg:max-w-5xl"
          />
        </ScrollReveal>

        <ScrollReveal className="mt-10 w-full sm:mt-14" delayMs={260}>
          <div className="text-left">
            <h3 className="text-2xl font-bold text-white sm:text-[28px] font-['Space_Grotesk','Manrope',sans-serif]">
              {t.rich('moreChecksTitle', {
                highlight: (chunks) => <span className="text-primary">{chunks}</span>,
              })}
            </h3>

            <div className="mt-8 grid grid-cols-1 gap-x-8 gap-y-8 sm:grid-cols-2 lg:grid-cols-3">
              {PER_REQUEST_CHECK_GROUPS.map((group) => (
                <div
                  key={group.id}
                  className="relative self-start border-l-2 border-primary py-1 pl-4 pr-8 pt-8"
                >
                  <span
                    aria-hidden="true"
                    className="material-symbols-rounded text-2xl! text-textGray absolute right-0 top-0 size-6"
                  >
                    {group.icon}
                  </span>

                  <h4 className="text-xl font-semibold text-white">
                    {t(`checks.${group.id}.title`)}
                  </h4>
                  <p className="mt-2 text-sm text-textGray">
                    {t(`checks.${group.id}.description`)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
