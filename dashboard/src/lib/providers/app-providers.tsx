'use client';

import type { ReactNode } from 'react';

import { NotificationProvider } from '@/components/ui/notifications';
import { QueryProvider } from '@/lib/providers/query-provider';

type AppProvidersProps = {
  children: ReactNode;
};

export function AppProviders({ children }: AppProvidersProps) {
  return (
    <QueryProvider>
      <NotificationProvider>{children}</NotificationProvider>
    </QueryProvider>
  );
}
