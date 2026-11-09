'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';

import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useSectionSidebarStore } from '@/store/section-sidebar-store';
import { DashboardNavItem } from '@/types/dashboard';
import { buildNavSegments } from '@/utils/dashboard-nav';
import { cn } from '@/utils/cn';

type SectionSidebarProps = {
  activeLabel?: string;
  ariaLabel: string;
  backHref?: string;
  backLabel?: string;
  className?: string;
  header?: ReactNode;
  headerBordered?: boolean;
  items: DashboardNavItem[];
  onItemSelect?: (item: DashboardNavItem) => void;
};

export function SectionSidebar({
  activeLabel,
  ariaLabel,
  backHref,
  backLabel,
  className,
  header,
  headerBordered = true,
  items,
  onItemSelect,
}: SectionSidebarProps) {
  const navLabels = useNavLabels();
  const shouldUseLocalState = Boolean(onItemSelect);
  const segments = buildNavSegments(items);

  const storedGroup = useSectionSidebarStore((state) => state.expandedGroupByKey[ariaLabel]);
  const setExpandedGroupForKey = useSectionSidebarStore((state) => state.setExpandedGroup);
  const expandedGroup =
    storedGroup !== undefined
      ? storedGroup
      : (items.find((item) => item.label === activeLabel)?.group ?? null);

  function toggleGroup(group: string) {
    setExpandedGroupForKey(ariaLabel, expandedGroup === group ? null : group);
  }

  function renderItem(item: DashboardNavItem): ReactNode {
    const isActive = activeLabel ? item.label === activeLabel : Boolean(item.isActive);

    return (
      <button
        key={item.label}
        type="button"
        disabled={!shouldUseLocalState}
        onClick={() => onItemSelect?.(item)}
        className={cn(
          'group relative flex h-8 w-full items-center gap-3 rounded-md px-2 py-1.5 text-left text-xs font-medium text-textGray transition',
          isActive ? 'border border-borderGray bg-cardBg text-white' : 'hover:text-white',
          !shouldUseLocalState && 'cursor-default',
        )}
      >
        {isActive ? (
          <span
            aria-hidden="true"
            className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary"
          />
        ) : null}
        <span
          className={cn(
            'flex h-6 w-6 shrink-0 items-center justify-center text-textGray transition',
            isActive ? 'text-primary' : 'group-hover:text-white',
          )}
        >
          <span className="material-symbols-rounded" aria-hidden="true">
            {item.icon}
          </span>
        </span>
        {navLabels.item(item)}
      </button>
    );
  }

  return (
    <aside
      className={cn(
        'hidden h-full w-60 shrink-0 flex-col self-stretch border-r border-borderGray bg-appBg text-white lg:flex',
        className,
      )}
    >
      {backHref ? (
        <div className="flex h-13 shrink-0 items-center border-b border-borderGray px-4">
          <Link
            href={backHref}
            className="flex h-8 items-center gap-2 text-xs font-medium text-primary transition hover:text-primary/80"
          >
            <span className="material-symbols-rounded text-base!" aria-hidden="true">
              arrow_back
            </span>
            {backLabel}
          </Link>
        </div>
      ) : null}

      {header ? (
        <div
          className={cn(
            'shrink-0 px-4',
            headerBordered ? 'border-b border-borderGray py-2.5' : 'pt-2.5',
          )}
        >
          {header}
        </div>
      ) : null}

      <nav aria-label={ariaLabel} className="min-h-0 flex-1 overflow-y-auto px-4 py-2.5">
        {segments.map((segment, index) => {
          const previousSegment = segments[index - 1];
          const needsDividerBeforeItem =
            segment.type === 'item' && previousSegment?.type === 'group';

          if (segment.type === 'item') {
            return (
              <div key={segment.item.label}>
                {needsDividerBeforeItem ? (
                  <div className="-mx-4 mt-2.5 border-t border-borderGray pt-2.5" />
                ) : null}
                {renderItem(segment.item)}
              </div>
            );
          }

          const isGroupOpen = segment.group === expandedGroup;

          return (
            <div key={`group-${segment.group}`}>
              <div className="-mx-4 mt-2.5 border-t border-borderGray pt-2.5" />

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

              <div
                className="grid transition-[grid-template-rows] duration-200 ease-in-out"
                style={{ gridTemplateRows: isGroupOpen ? '1fr' : '0fr' }}
              >
                <div className="overflow-hidden">{segment.items.map(renderItem)}</div>
              </div>
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
