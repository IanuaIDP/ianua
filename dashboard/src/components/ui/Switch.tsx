'use client';

import type { ButtonHTMLAttributes, ReactNode } from 'react';

import { cn } from '@/utils/cn';

type SwitchProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onChange' | 'type' | 'value'> & {
  checked: boolean;
  description?: ReactNode;
  label?: ReactNode;
  onCheckedChange: (checked: boolean) => void;
};

export function Switch({
  checked,
  className,
  description,
  disabled,
  label,
  onCheckedChange,
  ...props
}: SwitchProps) {
  return (
    <div className={cn('flex items-center justify-between gap-4', className)}>
      {label || description ? (
        <div className="min-w-0">
          {label ? <p className="text-sm font-medium text-white">{label}</p> : null}
          {description ? <p className="mt-0.5 text-xs text-textGray">{description}</p> : null}
        </div>
      ) : null}
      <button
        {...props}
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onCheckedChange(!checked)}
        className={cn(
          'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition disabled:pointer-events-none disabled:opacity-40',
          checked ? 'bg-primary' : 'bg-textGray',
        )}
      >
        <span
          className={cn(
            'size-4 rounded-full bg-white transition-transform',
            checked ? 'translate-x-4' : 'translate-x-0',
          )}
        />
      </button>
    </div>
  );
}
