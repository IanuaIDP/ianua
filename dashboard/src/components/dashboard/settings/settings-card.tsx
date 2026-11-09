import type { ReactNode } from 'react';

import { cn } from '@/utils/cn';

type SettingsCardProps = {
  children: ReactNode;
  className?: string;
  description?: string;
  headerAction?: ReactNode;
  title: string;
  titleClassName?: string;
  titleIcon?: ReactNode;
};

export function SettingsCard({
  children,
  className,
  description,
  headerAction,
  title,
  titleClassName,
  titleIcon,
}: SettingsCardProps) {
  return (
    <section className={cn('rounded-lg border border-borderGray bg-cardBg px-4 py-4', className)}>
      <div className="mb-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-2">
          {titleIcon ? <span className="flex h-5 shrink-0 items-center">{titleIcon}</span> : null}
          <div>
            <h2 className={cn('text-base font-bold leading-5 text-white', titleClassName)}>
              {title}
            </h2>
            {description ? (
              <p className="mt-2.5 text-xs font-medium text-textGray">{description}</p>
            ) : null}
          </div>
        </div>
        {headerAction ? <div className="shrink-0">{headerAction}</div> : null}
      </div>
      {children}
    </section>
  );
}
