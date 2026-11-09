'use client';

import type { ReactNode } from 'react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

export type RadioOption = {
  description?: ReactNode;
  label: string;
  value: string;
};

type RadioGroupProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  name: string;
  onChange: (value: string) => void;
  options: RadioOption[];
  value: string;
};

export function RadioGroup({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  name,
  onChange,
  options,
  value,
}: RadioGroupProps) {
  const errorMessage = useFieldError(error);

  return (
    <div className={containerClassName}>
      {label ? <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p> : null}

      <div className={cn('flex flex-col gap-1.5', className)} role="radiogroup" aria-label={label}>
        {options.map((option) => {
          const isSelected = option.value === value;

          return (
            <label
              key={option.value}
              className={cn(
                'group flex items-start gap-2 rounded-lg border px-3 py-2 transition',
                isSelected
                  ? 'border-focus/60 bg-focus/10'
                  : 'border-borderGray bg-surfaceRaised hover:border-white/20',
                disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
              )}
            >
              <span
                className={cn(
                  'mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border-2 transition',
                  isSelected ? 'border-focus' : 'border-textGray',
                )}
              >
                <input
                  type="radio"
                  name={name}
                  value={option.value}
                  checked={isSelected}
                  disabled={disabled}
                  onChange={() => onChange(option.value)}
                  className="absolute size-0 opacity-0"
                />
                {isSelected ? <span className="size-2 rounded-full bg-focus" /> : null}
              </span>
              <span className="min-w-0">
                <span className="block text-xs font-medium text-white">{option.label}</span>
                {option.description ? (
                  <span className="mt-0.5 block text-[10px] font-medium text-textGray">
                    {option.description}
                  </span>
                ) : null}
              </span>
            </label>
          );
        })}
      </div>

      {errorMessage ? (
        <p className="mt-1.5 text-xs font-medium text-error">{errorMessage}</p>
      ) : null}
      {!errorMessage && hint ? (
        <p className="mt-1.5 text-xs font-medium text-textGray">{hint}</p>
      ) : null}
    </div>
  );
}
