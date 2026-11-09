import Image from 'next/image';
import { redirect } from 'next/navigation';
import { useTranslations } from 'next-intl';

import howItWorksBackground from '@/assets/how-it-works-backgound.svg';
import securityAndWhyIanuaBackground from '@/assets/security-and-why-ianua.svg';
import useCaseBackground from '@/assets/use-case-background.svg';
import { AiAgentsSection } from '@/components/landing/ai-agents/ai-agents-section';
import { ContactSection } from '@/components/landing/contact/contact-section';
import { FaqSection } from '@/components/landing/faq/faq-section';
import { LandingFooter } from '@/components/landing/footer/landing-footer';
import { HeroSection } from '@/components/landing/hero/hero-section';
import { HowItWorksSection } from '@/components/landing/how-it-works/how-it-works-section';
import { PricingSection } from '@/components/landing/pricing/pricing-section';
import { ProblemSection } from '@/components/landing/problem/problem-section';
import { SecuritySection } from '@/components/landing/security/security-section';
import { ScrollStatusIndicator } from '@/components/landing/shared/scroll-status-indicator';
import { StatusDivider } from '@/components/landing/shared/status-divider';
import { UseCasesSection } from '@/components/landing/use-cases/use-cases-section';
import { WhatYouGetSection } from '@/components/landing/what-you-get/what-you-get-section';
import { WhyIanuaSection } from '@/components/landing/why-ianua/why-ianua-section';

export const dynamic = 'force-dynamic';

export default function LandingPage() {
  if (process.env.DEPLOYMENT === 'self_hosted') {
    redirect('/login');
  }

  return <LandingContent />;
}

function LandingContent() {
  const t = useTranslations('landing.dividers');

  return (
    <div>
      <ScrollStatusIndicator />
      <HeroSection />
      <ProblemSection />
      <StatusDivider id="access-denied-line" label={t('accessDenied')} tone="focus" />
      <section className="relative isolate overflow-hidden bg-appBg">
        <Image
          src={howItWorksBackground}
          alt=""
          className="pointer-events-none absolute inset-0 -z-10 h-full w-full select-none object-cover"
          aria-hidden="true"
        />
        <HowItWorksSection />
        <WhatYouGetSection />
        <AiAgentsSection />
      </section>
      <StatusDivider id="verifying-identity-line" label={t('verifyingIdentity')} tone="focus" />
      <section className="relative isolate overflow-hidden bg-appBg">
        <Image
          src={securityAndWhyIanuaBackground}
          alt=""
          className="pointer-events-none absolute inset-0 -z-10 h-full w-full select-none object-cover"
          aria-hidden="true"
        />
        <WhyIanuaSection />
        <SecuritySection />
      </section>
      <StatusDivider
        id="authentication-successful-line"
        label={t('accessGranted')}
        tone="primary"
      />
      <section className="relative isolate overflow-hidden bg-appBg">
        <Image
          src={useCaseBackground}
          alt=""
          className="pointer-events-none absolute inset-0 -z-10 h-full w-full select-none object-cover"
          aria-hidden="true"
        />
        <UseCasesSection />
        <PricingSection />
      </section>
      <StatusDivider id="opening-line" label={t('openingGateway')} tone="primary" />
      <FaqSection />
      <StatusDivider id="access-granted-line" label={t('welcomeIn')} tone="primary" />
      <ContactSection />
      <LandingFooter />
    </div>
  );
}
