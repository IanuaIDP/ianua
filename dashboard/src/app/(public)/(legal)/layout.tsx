import type { ReactNode } from 'react';

import { LandingFooter } from '@/components/landing/footer/landing-footer';
import { LegalHeader } from '@/components/legal/legal-header';

export default function LegalLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-appBg text-white">
      <LegalHeader />
      <main id="legal-scroll-container" className="min-h-0 flex-1 overflow-y-auto">
        {children}
        <LandingFooter showSectionNav={false} />
      </main>
    </div>
  );
}
