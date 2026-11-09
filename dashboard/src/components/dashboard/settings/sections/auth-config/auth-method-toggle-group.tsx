'use client';

import { useTranslations } from 'next-intl';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { cn } from '@/utils/cn';

type AuthMethodToggleGroupProps<T extends string> = {
  disabled?: boolean;
  labels: Record<T, string>;
  methods: readonly T[];
  onChange: (next: T[]) => void;
  value: T[];
};

export function AuthMethodToggleGroup<T extends string>({
  disabled,
  labels,
  methods,
  onChange,
  value,
}: AuthMethodToggleGroupProps<T>) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <div className="flex flex-wrap gap-2">
      {methods.map((method) => {
        const isActive = value.includes(method);
        const isLastRemaining = isActive && value.length <= 1;

        return (
          <FloatingTooltip
            key={method}
            content={t('methodRequired')}
            disabled={!isLastRemaining}
            placement="top"
          >
            <button
              type="button"
              aria-pressed={isActive}
              disabled={disabled || isLastRemaining}
              onClick={() => {
                const next = isActive ? value.filter((m) => m !== method) : [...value, method];

                onChange(next);
              }}
              className={cn(
                'rounded-full border px-3 py-1.5 text-xs font-medium transition disabled:pointer-events-none',
                isActive
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-borderGray bg-transparent text-textGray hover:text-white',
                disabled && 'opacity-60',
              )}
            >
              {labels[method]}
            </button>
          </FloatingTooltip>
        );
      })}
    </div>
  );
}
