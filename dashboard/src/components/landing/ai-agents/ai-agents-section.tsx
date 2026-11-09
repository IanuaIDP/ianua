import Image from 'next/image';
import Link from 'next/link';
import { useTranslations } from 'next-intl';

import aiAgentScreenshot from '@/assets/ai-agent.svg';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { AiAgentCard } from '@/components/landing/ai-agents/ai-agent-card';
import { AI_AGENTS_FEATURES } from '@/constants/landing';

export function AiAgentsSection() {
  const t = useTranslations('landing.aiAgents');
  const tCommon = useTranslations('common');

  return (
    <section id="ai-agents" className="px-6 pt-12 pb-16 sm:pb-24">
      <div className="mx-auto max-w-7xl">
        <ScrollReveal className="flex flex-col items-center text-center">
          <SectionBadge
            className="mx-auto border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="font-['Space_Grotesk','Manrope',sans-serif] mt-6 max-w-3xl text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              accent: (chunks) => <span className="block text-primary">{chunks}</span>,
            })}
          </h2>
        </ScrollReveal>

        <ScrollReveal className="mt-6 flex justify-center" delayMs={140}>
          <Image
            src={aiAgentScreenshot}
            alt={t('screenshotAlt')}
            className="h-auto w-full max-w-sm object-contain sm:max-w-lg md:max-w-3xl lg:max-w-5xl"
          />
        </ScrollReveal>

        <ScrollReveal className="mt-8 flex flex-col gap-6 sm:mt-12" delayMs={140}>
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
            {AI_AGENTS_FEATURES.slice(0, 3).map((feature) => (
              <AiAgentCard
                key={feature.id}
                icon={feature.icon}
                size={feature.size}
                tall={feature.tall}
                title={t(`features.${feature.id}.title`)}
                description={t(`features.${feature.id}.description`)}
              />
            ))}
          </div>
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
            {AI_AGENTS_FEATURES.slice(3, 6).map((feature) => (
              <AiAgentCard
                key={feature.id}
                icon={feature.icon}
                size={feature.size}
                tall={feature.tall}
                title={t(`features.${feature.id}.title`)}
                description={t(`features.${feature.id}.description`)}
              />
            ))}
          </div>

          <div className="text-center">
            <h2 className="mt-6 font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-[32px] sm:leading-12 lg:leading-16.25">
              {t.rich('ctaTitle', {
                highlight: (chunks) => <span className="text-primary">{chunks}</span>,
              })}
            </h2>

            <p className="mx-auto mt-4 max-w-3xl text-lg text-textGray">{t('ctaDescription')}</p>

            <div className="mt-6 flex flex-col justify-center gap-4 sm:flex-row">
              <Link
                href="/sign-up"
                className="inline-flex h-10.5 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
              >
                {tCommon('startFree')}
              </Link>
              <Link
                href="#"
                className="inline-flex h-10.5 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
              >
                {tCommon('bookDemo')}
                <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                  arrow_forward
                </span>
              </Link>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
