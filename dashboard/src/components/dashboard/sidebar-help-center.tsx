import { useTranslations } from 'next-intl';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { cn } from '@/utils/cn';

type SidebarHelpCenterProps = {
  isCollapsed?: boolean;
};

export function SidebarHelpCenter({ isCollapsed = false }: SidebarHelpCenterProps) {
  const t = useTranslations('dashboard.sidebar');

  return (
    <a
      href="/help-center"
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        'group relative flex h-8 items-center gap-3 rounded-md px-2 py-1.5 text-xs font-medium text-textGray transition hover:border-transparent hover:text-white',
        isCollapsed && 'justify-center px-0',
      )}
    >
      <span className="flex h-6 w-6 shrink-0 items-center justify-center text-textGray transition group-hover:text-white">
        <FloatingTooltip content={t('helpCenter')} disabled={!isCollapsed} placement="right">
          <span className="material-symbols-rounded" aria-hidden="true">
            help
          </span>
        </FloatingTooltip>
      </span>
      {!isCollapsed && t('helpCenter')}
    </a>
  );
}
