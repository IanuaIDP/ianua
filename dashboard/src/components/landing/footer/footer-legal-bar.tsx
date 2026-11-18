'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { CookieSettingsButton } from '@/components/analytics/cookie-settings-button';
import { LANDING_LEGAL_LINKS } from '@/constants/landing';

const IN_TAB_PATH_PREFIXES = ['/privacy-policy', '/terms-of-use', '/blog'];

export function FooterLegalBar() {
  const t = useTranslations('landing');
  const pathname = usePathname();
  const isOnLegalPage = IN_TAB_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );

  return (
    <div className="border-t border-borderGray px-8.75 py-4">
      <div className="flex max-w-8xl flex-col items-center justify-between gap-4 text-center text-sm text-textGray md:flex-row md:text-left">
        <p>{t('footer.copyright')}</p>

        <nav
          className="flex flex-wrap items-center justify-center gap-x-8 gap-y-2"
          aria-label={t('footer.legalNavigationAriaLabel')}
        >
          {LANDING_LEGAL_LINKS.map((link) => {
            const openInNewTab = link.href.startsWith('/') && !isOnLegalPage;

            return (
              <Link
                key={link.id}
                href={link.href}
                target={openInNewTab ? '_blank' : undefined}
                rel={openInNewTab ? 'noopener noreferrer' : undefined}
                className="transition-colors duration-200 hover:text-white"
              >
                {t(`legalLinks.${link.id}`)}
              </Link>
            );
          })}
          <CookieSettingsButton className="transition-colors duration-200 hover:text-white" />
        </nav>

        <p>
          {t.rich('footer.etymology', {
            brand: (chunks) => <span className="text-primary">{chunks}</span>,
          })}
        </p>
      </div>
    </div>
  );
}
