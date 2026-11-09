import { DashboardNavItem } from '@/types/dashboard';

export const DASHBOARD_NAV_ITEMS: DashboardNavItem[] = [
  { href: '/overview', label: 'Overview', icon: 'dashboard' },
  { activeMatch: 'nested', href: '/tenants', label: 'Tenants', icon: 'corporate_fare' },
  { href: '/team', label: 'Team', icon: 'groups' },
];

export const DASHBOARD_ROWS_PER_PAGE_OPTIONS = [10, 20, 50, 100];
