import type { ReactNode } from 'react';
import { redirect } from 'next/navigation';
import { getTranslations } from 'next-intl/server';

import { Analytics } from '@/components/analytics/analytics';
import { LandingFooter } from '@/components/landing/footer/landing-footer';
import { LegalHeader } from '@/components/legal/legal-header';
import { BLOG_NAV_ITEMS } from '@/constants/landing';

export default async function BlogLayout({ children }: { children: ReactNode }) {
  if (process.env.DEPLOYMENT === 'self_hosted') {
    redirect('/login');
  }

  const t = await getTranslations('blog');

  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-appBg text-white">
      <LegalHeader
        brandSuffix={t('brandSuffix')}
        navigationAriaLabel={t('navigationAriaLabel')}
        navItems={BLOG_NAV_ITEMS}
      />
      <main id="blog-scroll-container" className="min-h-0 flex-1 overflow-y-auto">
        {children}
        <LandingFooter showSectionNav={false} />
      </main>
      <Analytics />
    </div>
  );
}
