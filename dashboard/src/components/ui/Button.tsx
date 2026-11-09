'use client';

import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { cn } from '@/utils/cn';

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  isLoading?: boolean;
  variant?: 'primary' | 'outline' | 'focus';
};

export function Button({
  children,
  isLoading,
  variant = 'primary',
  className,
  ...props
}: ButtonProps) {
  const t = useTranslations('common');

  // Named variants rather than colour classes passed through `className`: an
  // override only wins if tailwind-merge recognises both sides as the same
  // group, and a custom colour it does not know leaves both rules standing —
  // whichever the stylesheet emits last then wins, which is how a modal's
  // purple action ended up rendering as the green default with white text on
  // it.
  const variantClasses = {
    focus: 'bg-focus text-white hover:bg-hoverBgPurple',
    outline: 'border border-primary text-primary hover:bg-primary/10',
    primary: 'bg-primary text-black hover:bg-btnWithBgHover',
  }[variant];

  return (
    <button
      {...props}
      disabled={isLoading || props.disabled}
      className={cn(
        'w-full whitespace-nowrap rounded-lg px-4 py-3 text-sm font-semibold tracking-wide transition duration-200 disabled:pointer-events-none disabled:opacity-30',
        variantClasses,
        className,
      )}
    >
      {isLoading ? t('loading') : children}
    </button>
  );
}
