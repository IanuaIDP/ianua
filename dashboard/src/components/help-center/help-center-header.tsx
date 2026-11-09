'use client';

import { useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useLocale, useTranslations } from 'next-intl';

import logoWithoutName from '@/assets/logo-without-name.svg';
import { HelpCenterSidebar } from '@/components/help-center/help-center-sidebar';
import { LanguageSwitcher } from '@/components/ui/language-switcher';
import {
  getDefaultHelpArticleRef,
  getHelpArticleBySlugPath,
  localizeHelpArticleRef,
} from '@/utils/help-center';

function useCurrentHelpArticleRef() {
  const pathname = usePathname();
  const locale = useLocale();
  const slug = pathname
    .replace(/^\/help-center\/?/, '')
    .split('/')
    .filter(Boolean);

  const ref = slug.length > 0 ? getHelpArticleBySlugPath(slug) : getDefaultHelpArticleRef();

  return ref ? localizeHelpArticleRef(ref, locale) : undefined;
}

export function HelpCenterHeader() {
  const t = useTranslations('helpCenter');
  const articleRef = useCurrentHelpArticleRef();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const breadcrumb = articleRef
    ? [articleRef.category.title, articleRef.parent?.title, articleRef.article.title].filter(
        (label): label is string => Boolean(label),
      )
    : [t('title')];

  useEffect(() => {
    document.body.classList.toggle('overflow-hidden', isMenuOpen);

    return () => {
      document.body.classList.remove('overflow-hidden');
    };
  }, [isMenuOpen]);

  return (
    <>
      <header className="z-20 flex h-13 shrink-0 items-center border-b border-borderGray bg-appBg">
        <div className="flex h-full shrink-0 items-center gap-3 px-4 lg:w-64 lg:border-r lg:border-borderGray">
          <Link
            href="/"
            className="flex items-center"
            aria-label={t('home')}
            onClick={() => setIsMenuOpen(false)}
          >
            <Image
              src={logoWithoutName}
              alt="ianua.io"
              className="h-6 w-auto object-contain"
              priority
            />
          </Link>
          <span className="hidden border-l border-borderGray pl-3 text-sm font-medium text-white sm:inline">
            {t('docs')}
          </span>
        </div>

        <div className="flex flex-1 items-center justify-between px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-2 text-xs font-medium text-textGray">
            {/* On narrow screens there isn't room for every level, so collapse
                everything before the current page into a single "…" crumb. */}
            {breadcrumb.length > 1 ? (
              <span className="flex min-w-0 shrink items-center gap-2 sm:hidden">
                <span className="shrink-0">&hellip;</span>
                <span className="material-symbols-rounded shrink-0 text-base!" aria-hidden="true">
                  chevron_right
                </span>
              </span>
            ) : null}
            <span className="truncate text-white sm:hidden">
              {breadcrumb[breadcrumb.length - 1]}
            </span>

            <span className="hidden min-w-0 items-center gap-2 sm:flex">
              {breadcrumb.map((label, index) => {
                const isLast = index === breadcrumb.length - 1;

                return (
                  <span className="flex min-w-0 items-center gap-2" key={label}>
                    {index > 0 ? (
                      <span
                        className="material-symbols-rounded shrink-0 text-base!"
                        aria-hidden="true"
                      >
                        chevron_right
                      </span>
                    ) : null}
                    <span className={isLast ? 'truncate text-white' : 'shrink-0'}>{label}</span>
                  </span>
                );
              })}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <LanguageSwitcher className="h-8" />
            <Link
              href="/login"
              className="hidden h-8 items-center gap-2 rounded-md px-3 text-sm font-medium text-white transition-colors duration-200 hover:text-primary lg:flex"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                login
              </span>
              {t('signIn')}
            </Link>
            <Link
              href="#"
              className="hidden h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg lg:flex"
            >
              {t('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
            <button
              type="button"
              className="flex size-8 items-center justify-center rounded-md text-white/80 transition-colors duration-200 lg:hidden"
              aria-controls="help-center-mobile-menu"
              aria-expanded={isMenuOpen}
              aria-label={isMenuOpen ? t('closeMenu') : t('openMenu')}
              onClick={() => setIsMenuOpen((value) => !value)}
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                {isMenuOpen ? 'close' : 'menu'}
              </span>
            </button>
          </div>
        </div>
      </header>

      {isMenuOpen ? (
        <div
          id="help-center-mobile-menu"
          className="fixed bottom-0 left-0 top-13 z-90 flex w-full flex-col overflow-y-auto border-r border-borderGray bg-appBg shadow-mobile-nav sm:w-96 md:w-104 lg:hidden"
        >
          <HelpCenterSidebar variant="mobile" onNavigate={() => setIsMenuOpen(false)} />

          <div className="grid gap-3 border-t border-borderGray p-4">
            <Link
              href="/login"
              onClick={() => setIsMenuOpen(false)}
              className="flex h-9 items-center justify-center gap-2 rounded-md border border-borderGray text-sm font-medium text-white transition-colors duration-200 hover:text-primary"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                login
              </span>
              {t('signIn')}
            </Link>
            <Link
              href="#"
              onClick={() => setIsMenuOpen(false)}
              className="inline-flex h-8 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {t('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
          </div>
        </div>
      ) : null}
    </>
  );
}
