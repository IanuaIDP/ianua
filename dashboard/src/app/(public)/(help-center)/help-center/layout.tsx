import type { ReactNode } from 'react';

import { HelpCenterHeader } from '@/components/help-center/help-center-header';
import { HelpCenterSidebar } from '@/components/help-center/help-center-sidebar';

export default function HelpCenterSectionLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full flex-col">
      <HelpCenterHeader />

      <div className="flex min-h-0 flex-1">
        <HelpCenterSidebar />
        {children}
      </div>
    </div>
  );
}
