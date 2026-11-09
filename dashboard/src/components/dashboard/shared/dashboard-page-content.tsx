import type { ReactNode } from 'react';

type DashboardPageContentProps = {
  children: ReactNode;
};

export function DashboardPageContent({ children }: DashboardPageContentProps) {
  return (
    <div className="flex h-[calc(100vh-4.25rem)] min-h-0 overflow-hidden px-4 pt-4">{children}</div>
  );
}
