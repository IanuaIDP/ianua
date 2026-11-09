import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { cn } from '@/utils/cn';

type SidebarSettingsProps = {
  activeHref?: string;
  href: string;
  isCollapsed?: boolean;
};

export function SidebarSettings({ activeHref, href, isCollapsed = false }: SidebarSettingsProps) {
  const t = useTranslations('dashboard.sidebar');
  const pathname = usePathname();
  const matchHref = activeHref ?? href;
  const isActive = pathname === matchHref || pathname.startsWith(`${matchHref}/`);

  return (
    <Link
      href={href}
      className={cn(
        'group relative flex h-8 items-center gap-3 rounded-md px-2 py-1.5 text-xs font-medium text-textGray transition',
        isCollapsed && 'justify-center px-0',
        isActive && 'border border-borderGray text-white bg-cardBg',
        isActive && isCollapsed && 'text-white',
        !isActive && 'hover:border-transparent hover:text-white',
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
          isActive && 'text-primary',
          !isActive && 'hover:border-transparent group-hover:text-white',
        )}
      >
        <FloatingTooltip content={t('settings')} disabled={!isCollapsed} placement="right">
          <span className="material-symbols-rounded" aria-hidden="true">
            settings
          </span>
        </FloatingTooltip>
      </span>
      {!isCollapsed && t('settings')}
    </Link>
  );
}
