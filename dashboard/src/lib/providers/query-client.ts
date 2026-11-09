import { QueryClient } from '@tanstack/react-query';

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        retry: 1,
        staleTime: 60 * 1000,
      },
    },
  });
}
