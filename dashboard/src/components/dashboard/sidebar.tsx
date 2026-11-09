'use client';

import Image from 'next/image';
import { useTranslations } from 'next-intl';
import logo from '@/assets/logo.svg';
import logoWithoutName from '@/assets/logo-without-name.svg';
import { Tooltip } from '@/components/ui/tooltip';
import { SidebarHelpCenter } from '@/components/dashboard/sidebar-help-center';
import { SidebarNav } from '@/components/dashboard/sidebar-nav';
import { SidebarNotifications } from '@/components/dashboard/sidebar-notifications';
import { SidebarSettings } from '@/components/dashboard/sidebar-settings';
import { SidebarUserProfile } from '@/components/dashboard/sidebar-user-profile';
import { DASHBOARD_NAV_ITEMS } from '@/constants/dashboard';
import { useAppStore } from '@/store/app-store';
import { cn } from '@/utils/cn';
import { getInitials } from '@/utils/initials';
import { DashboardNavItem } from '@/types/dashboard';

type SidebarProps = {
  locked?: boolean;
  navItems?: DashboardNavItem[];
  notificationsHref?: string;
  organizationName?: string;
  settingsActiveHref?: string;
  settingsHref?: string;
  tenantName?: string;
};

export function Sidebar({
  locked = false,
  navItems = DASHBOARD_NAV_ITEMS,
  notificationsHref = '/notifications',
  organizationName,
  settingsActiveHref,
  settingsHref,
  tenantName,
}: SidebarProps) {
  const t = useTranslations('dashboard.sidebar');
  const isSidebarOpen = useAppStore((state) => state.isSidebarOpen);
  const setSidebarOpen = useAppStore((state) => state.setSidebarOpen);
  const isCollapsed = locked || !isSidebarOpen;
  const entityName = tenantName ?? organizationName;

  const handleNavigate = () => {
    if (window.innerWidth < 768) {
      setSidebarOpen(false);
    }
  };

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-20 flex flex-col border-r border-borderGray bg-appBg text-white transition-[width] duration-200',
        isCollapsed ? 'w-13' : 'w-66.75',
      )}
    >
      <div
        className={cn(
          'h-13 shrink-0 border-b border-borderGray py-2.5',
          isCollapsed ? 'px-0' : 'px-4',
        )}
      >
        <div
          className={cn(
            'flex h-full items-center',
            isCollapsed ? 'justify-center' : 'justify-between',
          )}
        >
          {!isCollapsed && (
            <div className="flex items-center justify-center">
              <Image
                src={logo}
                alt="ianua.io"
                width={82}
                height={34}
                priority
                className="h-8.5 w-auto object-contain"
              />
            </div>
          )}
          {locked ? (
            <Image
              src={logoWithoutName}
              alt="ianua.io"
              width={29}
              height={32}
              priority
              className="w-7.25 h-8 object-contain"
            />
          ) : (
            <button
              type="button"
              aria-label={isCollapsed ? t('expand') : t('collapse')}
              onClick={() => setSidebarOpen(isCollapsed)}
              className="flex h-5 w-5 items-center justify-center text-textGray transition hover:text-white"
            >
              <Tooltip content={isCollapsed ? t('expand') : t('collapse')}>
                <span className="material-symbols-rounded" aria-hidden="true">
                  {isCollapsed ? 'left_panel_open' : 'left_panel_close'}
                </span>
              </Tooltip>
            </button>
          )}
        </div>
      </div>

      {entityName ? (
        <div
          className={cn(
            'shrink-0 border-b border-borderGray py-2.5',
            isCollapsed ? 'px-2' : 'px-4 ',
          )}
        >
          <div
            className={cn(
              'rounded-md border',
              isCollapsed ? 'flex justify-center border-transparent' : 'border-borderGray p-3',
            )}
          >
            <Tooltip content={entityName} disabled={!isCollapsed}>
              <div className="flex min-w-0 items-center gap-2">
                <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-[10px] font-bold text-black">
                  {getInitials(entityName)}
                </span>
                {!isCollapsed && (
                  <div className="min-w-0">
                    <p className="truncate text-xs font-semibold text-white">{entityName}</p>
                  </div>
                )}
              </div>
            </Tooltip>
          </div>
        </div>
      ) : null}

      <div className="scrollbar-hidden min-h-0 flex-1 overflow-y-auto">
        <div className={cn('border-b border-borderGray py-2.5', isCollapsed ? 'px-2' : 'px-4')}>
          <SidebarNav isCollapsed={isCollapsed} items={navItems} onNavigate={handleNavigate} />
        </div>

        <div className={cn('py-2.5', isCollapsed ? 'px-2' : 'px-4 ')}>
          <div>
            {settingsHref ? (
              <SidebarSettings
                activeHref={settingsActiveHref}
                href={settingsHref}
                isCollapsed={isCollapsed}
              />
            ) : null}
            <SidebarNotifications href={notificationsHref} isCollapsed={isCollapsed} />
            <SidebarHelpCenter isCollapsed={isCollapsed} />
          </div>
        </div>
      </div>

      <div className="shrink-0 border-t border-borderGray">
        <SidebarUserProfile isCollapsed={isCollapsed} />
      </div>
    </aside>
  );
}
