'use client';

import type { ReactNode } from 'react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type ColourPickerProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  onChange: (value: string) => void;
  value: string;
};

const FALLBACK = '#b1f15e';
const HEX = /^#[0-9a-fA-F]{6}$/;

export function ColourPicker({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  onChange,
  value,
}: ColourPickerProps) {
  const errorMessage = useFieldError(error);
  // The native swatch only accepts a full six-digit hex, so a half-typed
  // value shows the fallback rather than resetting what the person typed.
  const swatchValue = HEX.test(value) ? value : FALLBACK;

  return (
    <div className={containerClassName}>
      {label ? <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p> : null}

      <div
        className={cn(
          'flex h-9 items-center gap-2 rounded-lg border border-borderGray px-2 transition focus-within:border-focus',
          disabled && 'pointer-events-none opacity-60',
          className,
        )}
      >
        <label
          className="size-6 shrink-0 cursor-pointer overflow-hidden rounded-md border border-borderGray"
          style={{ backgroundColor: swatchValue }}
        >
          <input
            type="color"
            value={swatchValue}
            disabled={disabled}
            className="size-0 opacity-0"
            onChange={(event) => onChange(event.target.value)}
          />
          <span className="sr-only">{label ?? 'Pick a colour'}</span>
        </label>

        <input
          type="text"
          value={value}
          disabled={disabled}
          placeholder="#b1f15e"
          spellCheck={false}
          className="min-w-0 flex-1 bg-transparent font-mono text-xs font-medium text-white outline-none placeholder:text-textGray"
          onChange={(event) => onChange(event.target.value)}
        />
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
