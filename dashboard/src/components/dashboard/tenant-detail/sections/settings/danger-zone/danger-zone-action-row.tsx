'use client';

import { Button } from '@/components/ui/Button';
import { cn } from '@/utils/cn';

type DangerZoneActionRowTone = 'danger' | 'neutral' | 'warning';

const toneButtonClassName: Record<DangerZoneActionRowTone, string> = {
  danger: 'border-error bg-transparent text-error hover:bg-error/10',
  neutral: 'border-borderGray bg-surfaceChip text-white hover:bg-borderGray',
  warning: 'border-orange bg-transparent text-orange hover:bg-orange/10',
};

type DangerZoneActionRowProps = {
  buttonLabel: string;
  description: string;
  disabled?: boolean;
  isLast?: boolean;
  label: string;
  onClick: () => void;
  tone?: DangerZoneActionRowTone;
};

export function DangerZoneActionRow({
  buttonLabel,
  description,
  disabled = false,
  isLast = false,
  label,
  onClick,
  tone = 'warning',
}: DangerZoneActionRowProps) {
  return (
    <div
      className={cn(
        'flex w-full flex-col items-start sm:flex-row sm:items-center sm:justify-between',
        !isLast && 'border-b border-borderGray',
      )}
    >
      <div className="px-4 py-3">
        <p className="text-sm font-bold text-white">{label}</p>
        <span className="mt-2 text-xs font-medium text-textGray">{description}</span>
      </div>
      <div className="px-4 py-3">
        <Button
          type="button"
          onClick={onClick}
          disabled={disabled}
          className={cn(
            'w-auto border px-4 py-1.5 font-medium tracking-normal',
            toneButtonClassName[tone],
          )}
        >
          {buttonLabel}
        </Button>
      </div>
    </div>
  );
}
