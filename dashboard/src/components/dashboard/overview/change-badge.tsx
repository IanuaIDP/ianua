import type { ChangeTone } from '@/types/overview';
import { cn } from '@/utils/cn';

type ChangeBadgeProps = {
  value: string;
  tone: ChangeTone;
};

export function ChangeBadge({ value, tone }: ChangeBadgeProps) {
  const normalizedValue = value.replace(/^[+-]/, '');
  const isUp = tone === 'up';
  const isDown = tone === 'down';

  return (
    <span
      className={cn(
        'inline-flex h-4 w-fit items-center justify-center rounded-sm px-1.5 text-[10px] font-semibold leading-none',
        isUp && 'bg-primary/10 text-primary',
        isDown && 'bg-error/10 text-error',
        tone === 'flat' && 'bg-surfaceRaised text-textGray',
      )}
    >
      <span className="inline-flex items-center justify-center gap-px">
        <span
          className={cn(
            'material-symbols-rounded -ml-0.5 inline-flex size-3 shrink-0 items-center justify-center text-xs! leading-none! transition-transform',
            isUp && '-rotate-90',
            isDown && 'rotate-90',
          )}
          aria-hidden="true"
        >
          arrow_right_alt
        </span>
        <span className="inline-flex items-center leading-none">{normalizedValue}</span>
      </span>
    </span>
  );
}
