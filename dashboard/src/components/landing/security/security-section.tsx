import Image from 'next/image';
import { useTranslations } from 'next-intl';

import auditLogScreenshot from '@/assets/audit-log.svg';
import auditLogScreenshotCentered from '@/assets/audit-log-centered.svg';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { LandingHorizontalScrollContainer } from '@/components/landing/shared/landing-horizontal-scroll-container';
import { SecurityCard } from '@/components/landing/security/security-card';
import { SECURITY_CARDS } from '@/constants/landing';

export function SecuritySection() {
  const t = useTranslations('landing.security');

  return (
    <section id="security" className="pt-12 pb-16 sm:pb-24">
      <div className="relative lg:flex lg:min-h-137.5 lg:items-center">
        <div className="mx-auto max-w-7xl px-6">
          <div className="lg:grid lg:grid-cols-2 lg:items-center lg:gap-12">
            <ScrollReveal>
              <SectionBadge
                className="border-borderGray bg-cardBg px-4 py-2"
                labelClassName="text-xs font-normal text-textGray"
              >
                {t('badge')}
              </SectionBadge>

              <h2 className="mt-6 max-w-250 font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
                {t.rich('title', {
                  block: (chunks) => <span className="lg:block">{chunks}</span>,
                  highlight: (chunks) => <span className="text-primary">{chunks}</span>,
                })}
              </h2>
            </ScrollReveal>

            <div className="hidden lg:block" aria-hidden="true" />
          </div>

          <ScrollReveal className="mt-8 flex justify-center lg:hidden" delayMs={140}>
            <Image
              src={auditLogScreenshotCentered}
              alt={t('screenshotAlt')}
              className="h-auto w-full max-w-sm object-contain sm:max-w-lg md:max-w-2xl"
            />
          </ScrollReveal>
        </div>

        <ScrollReveal
          className="pointer-events-none absolute right-0 top-1/2 hidden w-[48vw] max-w-3xl -translate-y-1/2 lg:block"
          delayMs={140}
        >
          <Image src={auditLogScreenshot} alt={t('screenshotAlt')} className="w-full" />
        </ScrollReveal>
      </div>

      <div className="mx-auto max-w-7xl px-6">
        <ScrollReveal
          className="mt-8 overflow-hidden rounded-xl border border-borderGray bg-cardBg"
          delayMs={140}
        >
          <LandingHorizontalScrollContainer className="lg:grid lg:grid-cols-6 lg:overflow-visible">
            {SECURITY_CARDS.map((card, index) => (
              <SecurityCard
                key={card.id}
                icon={card.icon}
                title={t(`cards.${card.id}.title`)}
                description={t(`cards.${card.id}.description`)}
                isLast={index === SECURITY_CARDS.length - 1}
              />
            ))}
          </LandingHorizontalScrollContainer>
        </ScrollReveal>
      </div>
    </section>
  );
}
