import type { ReactNode } from 'react';

import { Analytics } from '@/components/analytics/analytics';
import { LandingHeader } from '@/components/landing/header/landing-header';

export default function LandingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-appBg text-white">
      <LandingHeader />
      <main id="landing-scroll-container" className="min-h-0 flex-1 overflow-y-auto">
        {children}
      </main>
      <Analytics />
    </div>
  );
}
