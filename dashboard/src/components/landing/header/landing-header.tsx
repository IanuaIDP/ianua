'use client';

import { useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useLocale, useTranslations } from 'next-intl';

import logo from '@/assets/logo.svg';
import { LandingSectionLink } from '@/components/landing/shared/landing-section-link';
import { LanguageSwitcher } from '@/components/ui/language-switcher';
import { LANDING_NAV_ITEMS } from '@/constants/landing';
import { DEFAULT_LOCALE } from '@/i18n/config';
import { useActiveLandingSection } from '@/hooks/landing/use-active-landing-section';
import { cn } from '@/utils/cn';

export function LandingHeader() {
  const t = useTranslations('landing');
  // Translated labels are longer than the English ones, so below 1700px the nav is tighter.
  const isCompactNav = useLocale() !== DEFAULT_LOCALE;
  const tCommon = useTranslations('common');
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const activeHref = useActiveLandingSection();

  useEffect(() => {
    document.body.classList.toggle('overflow-hidden', isMenuOpen);

    return () => {
      document.body.classList.remove('overflow-hidden');
    };
  }, [isMenuOpen]);

  return (
    <>
      <header className="sticky top-0 z-100 border-b border-borderGray bg-appBg/72 backdrop-blur-xl backdrop-saturate-150">
        <div className="flex h-16 w-full items-center justify-between px-8 py-4">
          <Link
            href="/"
            className="flex shrink-0 items-center"
            aria-label={t('header.homeAriaLabel')}
            onClick={() => setIsMenuOpen(false)}
          >
            <Image src={logo} alt="ianua.io" className="h-auto w-25 object-contain" priority />
          </Link>

          <nav
            className={cn(
              'hidden items-center 2xl:flex',
              isCompactNav ? 'gap-4 min-[1700px]:gap-7' : 'gap-7',
            )}
            aria-label={t('header.landingNavigation')}
          >
            {LANDING_NAV_ITEMS.map((item) => (
              <LandingSectionLink
                key={item.href}
                href={item.href}
                className={cn(
                  'whitespace-nowrap border-b border-transparent py-2 font-medium transition-colors duration-200 hover:border-primary hover:text-primary',
                  isCompactNav ? 'text-[13px] min-[1700px]:text-sm' : 'text-sm',
                  activeHref === item.href ? 'text-primary' : 'text-white/45',
                )}
              >
                {t(`nav.${item.id}`)}
              </LandingSectionLink>
            ))}
          </nav>

          <div className="flex shrink-0 items-center gap-2">
            <LanguageSwitcher />
            <Link
              href="/login"
              className="hidden h-8 items-center gap-2 rounded-md px-3 text-sm font-medium text-white transition-colors duration-200 hover:text-primary sm:flex"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                login
              </span>
              {tCommon('signIn')}
            </Link>
            <Link
              href="/sign-up"
              className="hidden sm:flex h-8 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
            >
              {tCommon('startFree')}
            </Link>
            <Link
              href="#"
              className="hidden sm:flex h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {tCommon('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
            <button
              type="button"
              className="flex h-9 w-9 items-center justify-center rounded-md border border-borderGray text-white/80 transition-colors duration-200 2xl:hidden"
              aria-controls="landing-mobile-menu"
              aria-expanded={isMenuOpen}
              aria-label={isMenuOpen ? tCommon('closeMenu') : tCommon('openMenu')}
              onClick={() => setIsMenuOpen((currentValue) => !currentValue)}
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                {isMenuOpen ? 'close' : 'menu'}
              </span>
            </button>
          </div>
        </div>
      </header>
      {isMenuOpen && (
        <div
          id="landing-mobile-menu"
          className="fixed bottom-0 right-0 top-16 z-90 w-full overflow-y-auto border-t border-borderGray bg-appBg px-8 py-5 shadow-mobile-nav sm:w-96 sm:border-l md:w-104 2xl:hidden"
        >
          <nav className="grid gap-0.5" aria-label={t('header.mobileNavigation')}>
            {LANDING_NAV_ITEMS.map((item) => (
              <LandingSectionLink
                key={item.href}
                href={item.href}
                onClick={() => setIsMenuOpen(false)}
                className={cn(
                  'rounded-md px-1 py-2 text-center text-base font-medium transition-colors duration-200 hover:text-primary',
                  activeHref === item.href ? 'text-primary' : 'text-white/70',
                )}
              >
                {t(`nav.${item.id}`)}
              </LandingSectionLink>
            ))}
          </nav>

          <div className="-mx-8 mt-4 border-t border-borderGray" />

          <div className="grid gap-3 pt-4 sm:hidden">
            <Link
              href="/login"
              onClick={() => setIsMenuOpen(false)}
              className="flex h-9 items-center justify-center gap-2 rounded-md border border-borderGray text-sm font-medium text-white transition-colors duration-200 hover:text-primary"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                login
              </span>
              {tCommon('signIn')}
            </Link>
            <Link
              href="/sign-up"
              className="inline-flex h-8 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
            >
              {tCommon('startFree')}
            </Link>
            <Link
              href="#"
              className="inline-flex h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {tCommon('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
          </div>
        </div>
      )}
    </>
  );
}
