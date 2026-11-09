import type { ReactNode } from 'react';
import { cn } from '@/utils/cn';

type TooltipProps = {
  children: ReactNode;
  content: ReactNode;
  disabled?: boolean;
  className?: string;
  side?:
    'bottom' | 'bottom-left' | 'bottom-right' | 'left' | 'right' | 'top' | 'top-left' | 'top-right';
  title?: string;
};

export function Tooltip({
  children,
  content,
  disabled = false,
  className,
  side = 'right',
  title,
}: TooltipProps) {
  if (disabled) {
    return children;
  }

  const isRich = Boolean(title);

  return (
    <span className={cn('group/tooltip relative inline-flex', className)}>
      {children}
      <span
        role="tooltip"
        className={cn(
          'pointer-events-none absolute z-50 rounded-lg px-2.5 py-2 text-xs font-medium opacity-0 shadow-lg transition group-hover/tooltip:opacity-100 group-focus-within/tooltip:opacity-100',
          isRich
            ? 'w-56 whitespace-normal border border-borderGray bg-appBg text-white'
            : 'whitespace-nowrap bg-white text-black',
          side === 'bottom' && 'left-1/2 top-full mt-2 -translate-x-1/2',
          side === 'bottom-left' && 'right-0 top-full mt-2',
          side === 'bottom-right' && 'left-0 top-full mt-2',
          side === 'left' && 'right-full top-1/2 mr-2 -translate-y-1/2',
          side === 'right' && 'left-full top-1/2 ml-2 -translate-y-1/2',
          side === 'top' && 'bottom-full left-1/2 mb-2 -translate-x-1/2',
          side === 'top-left' && 'bottom-full right-0 mb-2',
          side === 'top-right' && 'bottom-full left-0 mb-2',
        )}
      >
        {title ? <span className="mb-1 block font-semibold text-textGray">{title}</span> : null}
        {content}
      </span>
    </span>
  );
}
