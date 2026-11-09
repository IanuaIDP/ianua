'use client';

import NextLink, { type LinkProps as NextLinkProps } from 'next/link';
import type { AnchorHTMLAttributes, ReactNode } from 'react';

import { cn } from '@/utils/cn';

type AppLinkProps = NextLinkProps &
  Omit<AnchorHTMLAttributes<HTMLAnchorElement>, keyof NextLinkProps> & {
    children: ReactNode;
    variant?: 'plain' | 'outline';
    leftIcon?: ReactNode;
    rightIcon?: ReactNode;
  };

export function Link({
  children,
  variant = 'plain',
  leftIcon,
  rightIcon,
  className,
  ...props
}: AppLinkProps) {
  const variantClasses = {
    plain: 'text-xs text-primary hover:text-btnWithBgHover font-semibold tracking-widest',
    outline:
      'text-sm font-semibold tracking-widest text-primary border border-primary px-4 rounded-lg h-8 hover:bg-primary/10',
  };

  return (
    <NextLink
      {...props}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 transition',
        variantClasses[variant],
        className,
      )}
    >
      {leftIcon}
      {children}
      {rightIcon}
    </NextLink>
  );
}
