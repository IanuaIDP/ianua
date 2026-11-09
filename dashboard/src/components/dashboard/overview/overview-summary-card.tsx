import type { ReactNode } from 'react';
import { cn } from '@/utils/cn';

type OverviewSummaryCardProps = {
  title: string;
  children: ReactNode;
  className?: string;
  titleClassName?: string;
};

export function OverviewSummaryCard({
  title,
  children,
  className,
  titleClassName,
}: OverviewSummaryCardProps) {
  return (
    <section
      className={cn(
        'h-30.75 overflow-hidden rounded-xl border border-borderGray bg-cardBg p-4',
        className,
      )}
    >
      <h2 className={cn('text-base font-bold leading-tight text-white', titleClassName)}>
        {title}
      </h2>
      {children}
    </section>
  );
}
