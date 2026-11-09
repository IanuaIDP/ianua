'use client';

import { useRouter } from 'next/navigation';

import type { DashboardNavItem } from '@/types/dashboard';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';

export function useTenantSectionNavigation(tenantSlug: string) {
  const router = useRouter();

  return function handleTenantSectionChange(item: DashboardNavItem) {
    router.push(getTenantManagementTabHref(tenantSlug, item.label));
  };
}
