import Image from 'next/image';
import Link from 'next/link';
import { useTranslations } from 'next-intl';

import logo from '@/assets/logo.svg';
import { FooterLegalBar } from '@/components/landing/footer/footer-legal-bar';
import { LandingSectionLink } from '@/components/landing/shared/landing-section-link';
import { LANDING_NAV_ITEMS } from '@/constants/landing';

type LandingFooterProps = {
  showSectionNav?: boolean;
};

export function LandingFooter({ showSectionNav = true }: LandingFooterProps) {
  const t = useTranslations('landing.footer');
  const tNav = useTranslations('landing.nav');

  return (
    <footer id="landing-footer-border" className="border-t border-borderGray bg-appBg">
      <div className="mx-auto max-w-7xl px-6 md:px-30">
        <div className="flex flex-col items-center pt-8 pb-16 text-center">
          <Link href="/" className="flex items-center gap-3" aria-label={t('homeAriaLabel')}>
            <Image src={logo} alt="" className="h-auto w-[100px] object-contain" />
          </Link>

          <p className="mt-4 max-w-md text-xs font-light leading-5 text-white">{t('tagline')}</p>

          {showSectionNav && (
            <nav
              className="mt-12 flex flex-wrap justify-center gap-x-8 gap-y-4 text-sm font-medium text-textGray"
              aria-label={t('navigationAriaLabel')}
            >
              {LANDING_NAV_ITEMS.map((link) => (
                <LandingSectionLink
                  key={link.href}
                  href={link.href}
                  className="transition-colors duration-200 hover:text-white"
                >
                  {tNav(link.id)}
                </LandingSectionLink>
              ))}
            </nav>
          )}
        </div>
      </div>

      <FooterLegalBar />
    </footer>
  );
}
