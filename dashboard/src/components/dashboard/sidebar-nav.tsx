'use client';

import { useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { DASHBOARD_NAV_ITEMS } from '@/constants/dashboard';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { cn } from '@/utils/cn';
import { buildNavSegments, getFirstGroup, isNavItemActive } from '@/utils/dashboard-nav';
import { DashboardNavItem } from '@/types/dashboard';

type SidebarNavProps = {
  isCollapsed?: boolean;
  items?: DashboardNavItem[];
  linksDisabled?: boolean;
  onNavigate?: () => void;
};

export function SidebarNav({
  isCollapsed = false,
  items = DASHBOARD_NAV_ITEMS,
  linksDisabled = false,
  onNavigate,
}: SidebarNavProps) {
  const t = useTranslations('dashboard.nav');
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const [expandedGroup, setExpandedGroup] = useState<string | null>(() => getFirstGroup(items));
  const segments = buildNavSegments(items);

  function toggleGroup(group: string) {
    setExpandedGroup((current) => (current === group ? null : group));
  }

  function renderItem(item: DashboardNavItem): ReactNode {
    const isActive = item.isActive ?? isNavItemActive(pathname, item);
    const className = cn(
      'group relative flex h-8 items-center gap-3 rounded-md px-2 py-1.5 text-xs font-medium text-textGray transition',
      isCollapsed && 'justify-center px-0',
      isActive && 'border border-borderGray text-white bg-cardBg',
      isActive && isCollapsed && 'text-white',
      !isActive && !linksDisabled && 'hover:border-transparent hover:text-white',
      linksDisabled && 'cursor-default',
    );
    const content = (
      <>
        {isActive && (
          <span
            aria-hidden="true"
            className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary"
          />
        )}
        <span
          className={cn(
            'flex h-6 w-6 shrink-0 items-center justify-center text-textGray transition',
            isActive && 'text-primary',
            !isActive && !linksDisabled && 'group-hover:text-white',
          )}
        >
          <FloatingTooltip content={navLabels.item(item)} disabled={!isCollapsed} placement="right">
            <span className="material-symbols-rounded" aria-hidden="true">
              {item.icon}
            </span>
          </FloatingTooltip>
        </span>
        {!isCollapsed && navLabels.item(item)}
      </>
    );

    if (linksDisabled) {
      return (
        <span
          key={item.href}
          aria-current={isActive ? 'page' : undefined}
          aria-label={isCollapsed ? navLabels.item(item) : undefined}
          className={className}
        >
          {content}
        </span>
      );
    }

    return (
      <Link
        key={item.href}
        href={item.href}
        onClick={onNavigate}
        aria-label={isCollapsed ? navLabels.item(item) : undefined}
        className={className}
      >
        {content}
      </Link>
    );
  }

  return (
    <nav aria-label={t('ariaLabel')}>
      {segments.map((segment) => {
        if (segment.type === 'item') {
          return renderItem(segment.item);
        }

        const isGroupOpen = segment.group === expandedGroup;

        return (
          <div key={`group-${segment.group}`}>
            <div
              className={cn(
                'border-t border-borderGray pt-2.5 mt-2.5',
                isCollapsed ? '-mx-2' : '-mx-4',
              )}
            />

            {!isCollapsed && (
              <button
                type="button"
                onClick={() => toggleGroup(segment.group)}
                aria-expanded={isGroupOpen}
                className="flex w-full items-center justify-between px-2 text-[10px] font-semibold uppercase tracking-wide text-textGray/70 transition hover:text-white"
              >
                {navLabels.group(segment.group)}
                <span
                  className="material-symbols-rounded text-sm normal-case transition-transform duration-200 ease-in-out"
                  style={{ transform: isGroupOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
                  aria-hidden="true"
                >
                  expand_more
                </span>
              </button>
            )}

            <div
              className="grid transition-[grid-template-rows] duration-200 ease-in-out"
              style={{ gridTemplateRows: isCollapsed || isGroupOpen ? '1fr' : '0fr' }}
            >
              <div className={cn('overflow-hidden', isCollapsed && 'overflow-visible')}>
                {segment.items.map(renderItem)}
              </div>
            </div>
          </div>
        );
      })}
    </nav>
  );
}
