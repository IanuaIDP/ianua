'use client';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { cn } from '@/utils/cn';

type UserFieldIconButtonProps = {
  disabled?: boolean;
  icon: string;
  label: string;
  onClick: () => void;
  tone?: 'default' | 'danger';
};

/** An icon-only action in the fields popover, labelled by its tooltip. */
export function UserFieldIconButton({
  disabled,
  icon,
  label,
  onClick,
  tone = 'default',
}: UserFieldIconButtonProps) {
  return (
    <FloatingTooltip content={label} disabled={disabled}>
      <button
        type="button"
        aria-label={label}
        disabled={disabled}
        className={cn(
          'flex size-6 items-center justify-center rounded-md text-textGray transition hover:text-white disabled:pointer-events-none disabled:opacity-40',
          tone === 'danger' && 'hover:text-error',
        )}
        onClick={onClick}
      >
        <span className="material-symbols-rounded text-lg!" aria-hidden="true">
          {icon}
        </span>
      </button>
    </FloatingTooltip>
  );
}
