'use client';

import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useState } from 'react';

import { createQueryClient } from '@/lib/providers/query-client';

type QueryProviderProps = {
  children: ReactNode;
};

export function QueryProvider({ children }: QueryProviderProps) {
  const [queryClient] = useState(() => createQueryClient());

  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
