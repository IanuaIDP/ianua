'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { useActiveHelpSection } from '@/hooks/help-center/use-active-help-section';
import type { HelpSection } from '@/types/help-center';
import { cn } from '@/utils/cn';

type HelpCenterTocProps = {
  scrollContainerId: string;
  sections: HelpSection[];
};

export function HelpCenterToc({ scrollContainerId, sections }: HelpCenterTocProps) {
  const t = useTranslations('helpCenter');
  const sectionIds = useMemo(() => sections.map((section) => section.id), [sections]);
  const [activeId, setActiveId] = useActiveHelpSection(sectionIds, scrollContainerId);

  if (sections.length === 0) {
    return null;
  }

  return (
    <aside className="hidden h-full w-56 shrink-0 overflow-y-auto px-5 py-10 xl:block">
      <p className="mb-3 pl-4 font-['Space_Grotesk','Manrope',sans-serif] text-[12px] font-medium text-white">
        {t('content')}
      </p>
      <nav className="flex flex-col gap-0.5 border-l-2 border-borderGray">
        {sections.map((section) => {
          const isActive = section.id === activeId;

          return (
            <div key={section.id} className="relative">
              {isActive ? (
                <span
                  aria-hidden="true"
                  className="absolute inset-y-0 left-0 w-0.5 -translate-x-full bg-primary"
                />
              ) : null}
              <a
                href={`#${section.id}`}
                onClick={() => setActiveId(section.id)}
                className={cn(
                  "block truncate py-1.5 pl-4 font-['Manrope',sans-serif] text-[14px] font-medium transition",
                  isActive ? 'text-white' : 'text-textGray hover:text-white',
                )}
              >
                {section.heading}
              </a>
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
