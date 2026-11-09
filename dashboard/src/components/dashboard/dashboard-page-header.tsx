import type { ReactNode } from 'react';
import Link from 'next/link';
import { cn } from '@/utils/cn';

type DashboardPageHeaderProps = {
  icon?: string;
  title?: string;
  trail?: {
    badge?: ReactNode;
    href?: string;
    icon?: string;
    onClick?: () => void;
    title?: string;
  }[];
};

export function DashboardPageHeader({ icon, title, trail }: DashboardPageHeaderProps) {
  const items = trail ?? (icon && title ? [{ icon, title }] : []);

  return (
    <header className="border-b border-borderGray px-4 h-13">
      <div className="flex h-13 items-center gap-3">
        <h1 className="flex min-w-0 items-center gap-2 text-xs font-medium">
          {items.map((item, index) => {
            const isCurrent = index === items.length - 1;
            const isClickable = Boolean((item.href || item.onClick) && !isCurrent);
            const itemClassName = cn(
              'flex min-w-0 items-center gap-2 transition',
              isClickable ? 'text-textGray hover:text-white' : 'text-white',
            );
            const content = (
              <>
                {item.icon ? (
                  <span
                    className="flex size-6 shrink-0 items-center justify-center"
                    aria-hidden="true"
                  >
                    <span className="material-symbols-rounded">{item.icon}</span>
                  </span>
                ) : null}
                {item.title ? <span className="truncate">{item.title}</span> : null}
                {item.badge ? <span className="shrink-0">{item.badge}</span> : null}
              </>
            );

            return (
              <span key={`${item.title}-${index}`} className="flex min-w-0 items-center gap-2">
                {index > 0 ? (
                  <span className="material-symbols-rounded text-textGray" aria-hidden="true">
                    chevron_right
                  </span>
                ) : null}
                {item.onClick && !isCurrent ? (
                  <button type="button" onClick={item.onClick} className={itemClassName}>
                    {content}
                  </button>
                ) : item.href && !isCurrent ? (
                  <Link href={item.href} className={itemClassName}>
                    {content}
                  </Link>
                ) : (
                  <span className={itemClassName}>{content}</span>
                )}
              </span>
            );
          })}
        </h1>
      </div>
    </header>
  );
}
