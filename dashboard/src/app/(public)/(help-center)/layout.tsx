import type { ReactNode } from 'react';

import { Analytics } from '@/components/analytics/analytics';

export default function HelpCenterLayout({ children }: { children: ReactNode }) {
  return (
    <div className="h-screen bg-appBg text-white">
      {children}
      <Analytics />
    </div>
  );
}
