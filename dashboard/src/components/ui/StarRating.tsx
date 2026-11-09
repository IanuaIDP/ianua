'use client';

import type { ReactNode } from 'react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type StarRatingProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  max?: number;
  onChange: (value: number | null) => void;
  /** `null` when nobody has rated yet — distinct from a rating of zero. */
  value: number | null;
};

export function StarRating({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  max = 5,
  onChange,
  value,
}: StarRatingProps) {
  const errorMessage = useFieldError(error);
  const stars = Array.from({ length: max }, (_, index) => index + 1);

  return (
    <div className={containerClassName}>
      {label ? <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p> : null}

      <div className={cn('flex items-center gap-0.5', className)}>
        {stars.map((star) => {
          const isFilled = value !== null && star <= value;

          return (
            <button
              key={star}
              type="button"
              aria-label={`${star} of ${max}`}
              aria-pressed={isFilled}
              disabled={disabled}
              // Clicking the current rating again clears it, which is the only
              // way to take a rating back to "not rated".
              onClick={() => onChange(value === star ? null : star)}
              className={cn(
                'flex size-7 items-center justify-center rounded-md transition disabled:pointer-events-none disabled:opacity-40',
                isFilled ? 'text-orange' : 'text-textGray hover:text-white',
              )}
            >
              <span
                className="material-symbols-rounded text-lg!"
                style={isFilled ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                star
              </span>
            </button>
          );
        })}

        {value !== null ? (
          <button
            type="button"
            disabled={disabled}
            className="ml-1.5 text-[10px] font-semibold text-focus transition hover:text-focus/80 disabled:pointer-events-none disabled:opacity-60"
            onClick={() => onChange(null)}
          >
            Clear
          </button>
        ) : null}
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
