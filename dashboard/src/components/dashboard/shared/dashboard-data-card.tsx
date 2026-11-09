import type { ReactNode } from 'react';

import { Tooltip } from '@/components/ui/tooltip';
import { cn } from '@/utils/cn';

type DashboardDataCardProps = {
  actionLabel?: string;
  actionTooltip?: ReactNode;
  children: ReactNode;
  className?: string;
  description: string;
  errorMessage?: string;
  footer?: ReactNode;
  isActionDisabled?: boolean;
  isSecondaryActionDisabled?: boolean;
  onActionClick?: () => void;
  onSecondaryActionClick?: () => void;
  /** A custom control rendered before the actions, for anything a plain button can't do. */
  secondaryAction?: ReactNode;
  secondaryActionLabel?: string;
  secondaryActionTooltip?: ReactNode;
  tabs?: ReactNode;
  title: string;
  titleControl?: ReactNode;
};

export function DashboardDataCard({
  actionLabel,
  actionTooltip,
  children,
  className,
  description,
  errorMessage,
  footer,
  isActionDisabled = false,
  isSecondaryActionDisabled = false,
  onActionClick,
  onSecondaryActionClick,
  secondaryAction,
  secondaryActionLabel,
  secondaryActionTooltip,
  tabs,
  title,
  titleControl,
}: DashboardDataCardProps) {
  return (
    <section
      className={cn(
        'mx-auto flex max-h-full w-full max-w-360 flex-col self-start overflow-hidden rounded-lg border border-borderGray bg-cardBg',
        className,
      )}
    >
      <div className="flex shrink-0 flex-col gap-5 pb-6 px-4 pt-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-base font-bold leading-tight text-white">{title}</h2>
            {titleControl}
          </div>
          <p className="mt-2.5 text-xs font-medium text-textGray">{description}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 sm:self-start">
          {secondaryAction}
          {secondaryActionLabel && onSecondaryActionClick && (
            <Tooltip
              content={secondaryActionTooltip}
              disabled={!isSecondaryActionDisabled || !secondaryActionTooltip}
              side="bottom-left"
            >
              <button
                type="button"
                onClick={onSecondaryActionClick}
                disabled={isSecondaryActionDisabled}
                className={cn(
                  'inline-flex h-8 shrink-0 items-center gap-3 whitespace-nowrap rounded-lg border border-borderGray bg-surfaceChip px-4 text-sm font-medium text-white transition hover:bg-hoverBg',
                  isSecondaryActionDisabled && 'cursor-not-allowed opacity-50',
                )}
              >
                <span>{secondaryActionLabel}</span>
              </button>
            </Tooltip>
          )}
          {actionLabel && onActionClick && (
            <Tooltip
              content={actionTooltip}
              disabled={!isActionDisabled || !actionTooltip}
              side="bottom"
            >
              <button
                type="button"
                onClick={onActionClick}
                disabled={isActionDisabled}
                className={cn(
                  'inline-flex h-8 shrink-0 items-center gap-3 whitespace-nowrap rounded-lg bg-focus px-4 text-sm font-medium text-white transition hover:bg-focus/90',
                  isActionDisabled && 'cursor-not-allowed opacity-50',
                )}
              >
                <span>{actionLabel}</span>
              </button>
            </Tooltip>
          )}
        </div>
      </div>

      {errorMessage && (
        <div className="mx-4 mb-6 shrink-0 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {errorMessage}
        </div>
      )}

      {tabs && <div className="shrink-0">{tabs}</div>}
      {children}
      {footer && <div className="shrink-0">{footer}</div>}
    </section>
  );
}
