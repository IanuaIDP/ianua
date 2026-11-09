import type { ReactNode } from 'react';

export default function HelpCenterLayout({ children }: { children: ReactNode }) {
  return <div className="h-screen bg-appBg text-white">{children}</div>;
}
