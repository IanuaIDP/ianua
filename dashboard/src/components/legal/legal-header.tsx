'use client';

import { useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useLocale, useTranslations } from 'next-intl';

import logo from '@/assets/logo.svg';
import { LanguageSwitcher } from '@/components/ui/language-switcher';
import { LEGAL_NAV_ITEMS } from '@/constants/landing';
import { DEFAULT_LOCALE } from '@/i18n/config';
import { cn } from '@/utils/cn';

export function LegalHeader() {
  const t = useTranslations('legal.header');
  const tCommon = useTranslations('common');
  const tLegalLinks = useTranslations('landing.legalLinks');
  const tHeader = useTranslations('landing.header');
  // Translated labels are longer, so the full header needs more room before it
  // replaces the menu button.
  const hasLongLabels = useLocale() !== DEFAULT_LOCALE;
  const showFromDesktop = hasLongLabels ? 'min-[1320px]:flex' : 'lg:flex';
  const hideFromDesktop = hasLongLabels ? 'min-[1320px]:hidden' : 'lg:hidden';
  const pathname = usePathname();
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  useEffect(() => {
    document.body.classList.toggle('overflow-hidden', isMenuOpen);

    return () => {
      document.body.classList.remove('overflow-hidden');
    };
  }, [isMenuOpen]);

  return (
    <header className="sticky top-0 z-100 border-b border-white/10 bg-appBg">
      <div className="flex h-16 w-full items-center justify-between px-4 py-4 sm:px-8">
        <div className="flex shrink-0 items-center gap-3">
          <Link
            href="/"
            className="flex items-center"
            aria-label={tHeader('homeAriaLabel')}
            onClick={() => setIsMenuOpen(false)}
          >
            <Image src={logo} alt="ianua.io" className="h-auto w-25 object-contain" priority />
          </Link>
          <span className="hidden border-l border-white/10 pl-3 text-sm text-white sm:inline">
            {t('brandSuffix')}
          </span>
        </div>

        <nav
          className={cn('hidden items-center gap-8', showFromDesktop)}
          aria-label={t('navigationAriaLabel')}
        >
          {LEGAL_NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href;

            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'py-2 text-sm font-medium transition-colors duration-200',
                  isActive ? ' text-primary' : 'text-white/45 hover:text-primary',
                )}
              >
                {tLegalLinks(item.id)}
              </Link>
            );
          })}
        </nav>

        <div className="flex shrink-0 items-center gap-2">
          <LanguageSwitcher />
          <Link
            href="/login"
            className={cn(
              'hidden h-8 items-center gap-2 rounded-md px-3 text-sm font-medium text-white transition-colors duration-200 hover:text-primary',
              showFromDesktop,
            )}
          >
            <span className="material-symbols-rounded" aria-hidden="true">
              login
            </span>
            {tCommon('signIn')}
          </Link>
          <Link
            href="/sign-up"
            className={cn(
              'hidden h-8 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple',
              showFromDesktop,
            )}
          >
            {tCommon('startFree')}
          </Link>
          <Link
            href="#"
            className={cn(
              'hidden h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg',
              showFromDesktop,
            )}
          >
            {tCommon('bookDemo')}
            <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
              arrow_forward
            </span>
          </Link>
          <button
            type="button"
            className={cn(
              'flex h-9 w-9 items-center justify-center rounded-md border border-borderGray text-white/80 transition-colors duration-200',
              hideFromDesktop,
            )}
            aria-controls="legal-mobile-menu"
            aria-expanded={isMenuOpen}
            aria-label={isMenuOpen ? tCommon('closeMenu') : tCommon('openMenu')}
            onClick={() => setIsMenuOpen((value) => !value)}
          >
            <span className="material-symbols-rounded" aria-hidden="true">
              {isMenuOpen ? 'close' : 'menu'}
            </span>
          </button>
        </div>
      </div>

      {isMenuOpen ? (
        <div
          id="legal-mobile-menu"
          className={cn(
            'absolute inset-x-0 top-full z-90 overflow-y-auto border-t border-borderGray bg-appBg px-8 py-5 shadow-mobile-nav',
            hideFromDesktop,
          )}
        >
          <nav className="grid gap-0.5" aria-label={t('navigationAriaLabel')}>
            {LEGAL_NAV_ITEMS.map((item) => {
              const isActive = pathname === item.href;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setIsMenuOpen(false)}
                  className={cn(
                    'rounded-md px-1 py-2 text-center text-base font-medium transition-colors duration-200 hover:text-primary',
                    isActive ? 'text-primary' : 'text-white/70',
                  )}
                >
                  {tLegalLinks(item.id)}
                </Link>
              );
            })}
          </nav>

          <div className="-mx-8 mt-4 border-t border-borderGray" />

          <div className="grid gap-3 pt-4">
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
              onClick={() => setIsMenuOpen(false)}
              className="inline-flex h-8 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
            >
              {tCommon('startFree')}
            </Link>
            <Link
              href="#"
              onClick={() => setIsMenuOpen(false)}
              className="inline-flex h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {tCommon('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
          </div>
        </div>
      ) : null}
    </header>
  );
}
