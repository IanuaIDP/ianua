'use client';

import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { LocaleSync } from '@/components/dashboard/locale-sync';
import { NoTenantAccess } from '@/components/dashboard/no-tenant-access';
import { OrganizationNotificationWebSocket } from '@/components/dashboard/organization-notification-websocket';
import { Sidebar } from '@/components/dashboard/sidebar';
import { TenantNotificationWebSocket } from '@/components/dashboard/tenant-notification-websocket';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { DASHBOARD_NAV_ITEMS } from '@/constants/dashboard';
import { getTenantNavItems } from '@/utils/dashboard-nav';
import { getTenantPath } from '@/utils/dashboard-routes';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSessionMove } from '@/hooks/tenants/use-tenant-session-move';
import { withSignInReturn } from '@/lib/auth/sign-in-return';
import { useAppStore } from '@/store/app-store';
import { useAuthStore } from '@/store/auth-store';
import { cn } from '@/utils/cn';
import {
  getManagedTenantSlug,
  getTenantRouteContext,
  isTenantLoginRoute,
  isTenantSubDetailRoute,
} from '@/utils/dashboard-routes';
import { getOrgRights, isTenantAccessGated } from '@/utils/org-role';
import {
  filterTenantNavItemsByPermission,
  getTenantFormPermission,
  getTenantSectionResource,
} from '@/utils/tenant-section-permissions';

function TenantAccessMessage({ description, title }: { description: string; title: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      <span className="material-symbols-rounded text-4xl text-textGray" aria-hidden="true">
        lock
      </span>
      <h1 className="text-lg font-semibold text-white">{title}</h1>
      <p className="max-w-sm text-sm text-textGray">{description}</p>
    </div>
  );
}

export function DashboardLayout({ children }: { children: ReactNode }) {
  const t = useTranslations('dashboard.layout');
  const router = useRouter();
  const pathname = usePathname();
  const isPublicTenantLoginRoute = isTenantLoginRoute(pathname);
  const isSidebarOpen = useAppStore((state) => state.isSidebarOpen);
  const setSidebarOpen = useAppStore((state) => state.setSidebarOpen);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const sessionOrganizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const sessionOrganizationName = useAuthStore((state) => state.user?.organizationName);
  const sessionTenantSlug = useAuthStore((state) => state.user?.tenantSlug);
  const sessionTenantName = useAuthStore((state) => state.user?.tenantName);
  const routeTenantContext = getTenantRouteContext(pathname);
  const organizationSlug = routeTenantContext?.orgSlug ?? sessionOrganizationSlug;
  const tenantSlug = routeTenantContext?.tenantSlug ?? sessionTenantSlug;
  const isTenantView = Boolean(routeTenantContext);
  const managedTenantSlug = getManagedTenantSlug(pathname);
  const isMainSidebarLocked =
    Boolean(managedTenantSlug) ||
    (isTenantView && isTenantSubDetailRoute(pathname)) ||
    (!isTenantView && pathname === '/settings');
  const tenantPath =
    organizationSlug && tenantSlug ? getTenantPath(organizationSlug, tenantSlug) : undefined;
  const {
    canView: canViewTenantResource,
    hasPermission: hasTenantPermission,
    isLoading: isLoadingTenantPermissions,
  } = useTenantPermissions();
  const sectionResource = getTenantSectionResource(pathname);
  const formPermission = getTenantFormPermission(pathname);
  const isSectionForbidden =
    !isLoadingTenantPermissions &&
    ((sectionResource !== null && !canViewTenantResource(sectionResource)) ||
      (formPermission !== null &&
        !hasTenantPermission(formPermission.resource, formPermission.action)));
  const sidebarNavItems = routeTenantContext
    ? filterTenantNavItemsByPermission(
        getTenantNavItems(routeTenantContext.orgSlug, routeTenantContext.tenantSlug),
        canViewTenantResource,
      )
    : undefined;
  const unauthenticatedLoginPath = isTenantView && tenantPath ? `${tenantPath}/login` : '/login';
  const access = useAuthStore((state) => state.access);
  const { refresh: refreshOrgAccess } = useOrgAccess();
  const viewedTenantSlug = routeTenantContext?.tenantSlug ?? managedTenantSlug;
  const isMovingSession = useTenantSessionMove(isAuthenticated ? viewedTenantSlug : null);
  const isGatedOrgRole = isTenantAccessGated(access?.role);
  const hasNoTenantAccess =
    isGatedOrgRole &&
    Boolean(viewedTenantSlug) &&
    !access?.tenants.some((tenant) => tenant.slug === viewedTenantSlug);
  const orgRights = getOrgRights(access?.role);
  const organizationNavItems = DASHBOARD_NAV_ITEMS.filter(
    (item) =>
      (item.href !== '/tenants' || orgRights.canViewTenants) &&
      (item.href !== '/team' || orgRights.canViewMembers),
  );
  const isOrganizationPageForbidden =
    access !== null &&
    ((pathname === '/tenants' && !orgRights.canViewTenants) ||
      (pathname === '/team' && !orgRights.canViewMembers));

  useEffect(() => {
    if (isGatedOrgRole && viewedTenantSlug) {
      void refreshOrgAccess().catch(() => undefined);
    }
  }, [isGatedOrgRole, refreshOrgAccess, viewedTenantSlug]);

  useEffect(() => {
    if (!isPublicTenantLoginRoute && isHydrated && !isAuthenticated) {
      router.replace(withSignInReturn(unauthenticatedLoginPath, pathname, window.location.search));
    }
  }, [
    isAuthenticated,
    isHydrated,
    isPublicTenantLoginRoute,
    pathname,
    router,
    unauthenticatedLoginPath,
  ]);

  if (isPublicTenantLoginRoute) {
    return <>{children}</>;
  }

  if (!isHydrated || !isAuthenticated) {
    return (
      <div className="flex h-screen items-center justify-center bg-appBg text-sm font-semibold text-textGray">
        {t('loading')}
      </div>
    );
  }

  return (
    <div className="h-screen overflow-hidden bg-appBg text-white">
      <LocaleSync />
      {!isTenantView ? <OrganizationNotificationWebSocket /> : null}
      {isTenantView ? <TenantNotificationWebSocket /> : null}

      {isSidebarOpen && (
        <button
          type="button"
          aria-label={t('closeSidebarOverlay')}
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 z-10 bg-appBg/60 min-[1440px]:hidden"
        />
      )}

      <Sidebar
        locked={isMainSidebarLocked}
        navItems={sidebarNavItems ?? organizationNavItems}
        notificationsHref={isTenantView && tenantPath ? `${tenantPath}/notifications` : undefined}
        organizationName={!isTenantView ? sessionOrganizationName : undefined}
        settingsActiveHref={isTenantView && tenantPath ? `${tenantPath}/settings` : '/settings'}
        settingsHref={
          isTenantView
            ? tenantPath
              ? `${tenantPath}/settings/account`
              : undefined
            : '/settings?tab=General'
        }
        tenantName={isTenantView ? sessionTenantName : undefined}
      />

      <main
        className={cn(
          'dashboard-main h-screen overflow-hidden transition-[margin] duration-200',
          isSidebarOpen && !isMainSidebarLocked && 'dashboard-main--sidebar-open',
        )}
      >
        {isMovingSession ? (
          <div className="flex h-screen items-center justify-center text-sm font-semibold text-textGray">
            {t('loading')}
          </div>
        ) : hasNoTenantAccess ? (
          <NoTenantAccess
            description={
              orgRights.canReachTenants
                ? t('noTenantAccessDescription')
                : t('noTenantReachDescription')
            }
          />
        ) : isOrganizationPageForbidden ? (
          <TenantAccessMessage
            title={t('noPageAccessTitle')}
            description={t('noOrganizationPageAccessDescription')}
          />
        ) : isSectionForbidden ? (
          <div className="flex h-screen overflow-hidden">
            {managedTenantSlug ? (
              <TenantSidebar
                tenantSlug={managedTenantSlug}
                variant="management"
                onItemSelect={(item) => router.push(item.href)}
              />
            ) : null}
            <div className="min-w-0 flex-1">
              <TenantAccessMessage
                title={t('noPageAccessTitle')}
                description={t('noPageAccessDescription')}
              />
            </div>
          </div>
        ) : (
          children
        )}
      </main>
    </div>
  );
}
