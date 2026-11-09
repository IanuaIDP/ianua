'use client';

import type { ButtonHTMLAttributes, ReactNode } from 'react';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { cn } from '@/utils/cn';

type ToolButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: string;
  label: string;
  showLabel?: boolean;
};

/** A quiet button of the builder's bars: an icon, and its name when there is room. */
export function ToolButton({
  className,
  icon,
  label,
  showLabel = false,
  ...props
}: ToolButtonProps) {
  return (
    <FloatingTooltip content={label} disabled={showLabel}>
      <button
        {...props}
        type="button"
        aria-label={label}
        className={cn(
          'inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-xs font-medium text-textGray transition hover:bg-hoverBg hover:text-white disabled:pointer-events-none disabled:opacity-30',
          className,
        )}
      >
        <span className="material-symbols-rounded text-lg!" aria-hidden="true">
          {icon}
        </span>
        {showLabel ? label : null}
      </button>
    </FloatingTooltip>
  );
}

type SmallButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  icon?: string;
};

/** A small action inside the panel or an alert. */
export function SmallButton({ children, className, icon, ...props }: SmallButtonProps) {
  return (
    <button
      {...props}
      type="button"
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg bg-surfaceChip px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-borderGray disabled:pointer-events-none disabled:opacity-30',
        className,
      )}
    >
      {icon ? (
        <span className="material-symbols-rounded text-base!" aria-hidden="true">
          {icon}
        </span>
      ) : null}
      {children}
    </button>
  );
}
