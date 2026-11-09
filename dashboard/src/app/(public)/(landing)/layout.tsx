import type { ReactNode } from 'react';

import { LandingHeader } from '@/components/landing/header/landing-header';

export default function LandingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-appBg text-white">
      <LandingHeader />
      <main id="landing-scroll-container" className="min-h-0 flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
