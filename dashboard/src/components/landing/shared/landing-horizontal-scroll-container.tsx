'use client';

import { type ReactNode } from 'react';
import { cn } from '@/utils/cn';

type LandingHorizontalScrollContainerProps = {
  children: ReactNode;
  className?: string;
};

export function LandingHorizontalScrollContainer({
  children,
  className,
}: LandingHorizontalScrollContainerProps) {
  return (
    <div className="relative bg-linear-to-r from-scrollFade/70 to-appBg">
      <div className={cn('flex overflow-x-auto', className)}>{children}</div>
    </div>
  );
}
