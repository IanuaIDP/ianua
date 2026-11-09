'use client';

import { cn } from '@/utils/cn';

export type SegmentedControlOption<Value extends string> = {
  label: string;
  value: Value;
};

type SegmentedControlProps<Value extends string> = {
  ariaLabel: string;
  onChange: (value: Value) => void;
  options: SegmentedControlOption<Value>[];
  value: Value;
};

/**
 * A choice between a few mutually exclusive views of a card.
 *
 * Distinct from `DashboardTabs` on purpose: tabs filter one list, and this
 * swaps the list for a different one. Giving them the same shape would promise
 * the wrong thing about what pressing them does.
 */
export function SegmentedControl<Value extends string>({
  ariaLabel,
  onChange,
  options,
  value,
}: SegmentedControlProps<Value>) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className="inline-flex w-fit shrink-0 items-center rounded-lg bg-surfaceRaised p-1 text-xs font-bold"
    >
      {options.map((option) => {
        const isActive = option.value === value;

        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => {
              if (!isActive) {
                onChange(option.value);
              }
            }}
            className={cn(
              'shrink-0 whitespace-nowrap rounded-md px-3 py-1.5 text-xs transition',
              isActive
                ? 'cursor-default! bg-primary/15 font-semibold text-primary'
                : 'font-medium text-textGray hover:text-white',
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
