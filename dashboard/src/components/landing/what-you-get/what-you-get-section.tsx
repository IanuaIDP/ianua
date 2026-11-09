import Image from 'next/image';
import { useTranslations } from 'next-intl';

import accessEnforcedImage from '@/assets/access-enforced.svg';
import loginFlowImage from '@/assets/login-flow.svg';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { FeatureCard } from '@/components/landing/what-you-get/feature-card';

export function WhatYouGetSection() {
  const t = useTranslations('landing.whatYouGet');

  return (
    <section id="what-you-get" className="px-6 pt-12 pb-16 sm:pb-24">
      <div className="mx-auto max-w-7xl">
        <ScrollReveal>
          <SectionBadge
            className="border-borderGray bg-cardBg px-4 py-2"
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

        <ScrollReveal
          className="mt-8 grid grid-cols-1 gap-y-8 sm:mt-12 lg:grid-cols-2 lg:gap-x-12"
          delayMs={140}
        >
          <FeatureCard>
            <div className="flex items-center">
              <Image src={loginFlowImage} alt="" className="block h-auto w-full object-contain" />
            </div>
          </FeatureCard>

          <FeatureCard
            title={t('features.access.title')}
            description={t('features.access.description')}
            className="border-b border-borderGray pb-8"
          />

          <FeatureCard
            title={t('features.identity.title')}
            description={t('features.identity.description')}
            className="border-b border-borderGray pb-8"
          />

          <FeatureCard
            title={t('features.provable.title')}
            description={t('features.provable.description')}
          />

          <FeatureCard
            title={t('features.customers.title')}
            description={t('features.customers.description')}
          />

          <FeatureCard>
            <div className="flex items-center justify-center">
              <Image
                src={accessEnforcedImage}
                alt=""
                className="block h-auto w-auto max-w-full object-contain drop-shadow-lg"
              />
            </div>
          </FeatureCard>
        </ScrollReveal>
      </div>
    </section>
  );
}
