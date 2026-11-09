'use client';

import type { InputHTMLAttributes, ReactNode } from 'react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type CheckboxProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  containerClassName?: string;
  error?: FieldError | string;
  label?: ReactNode;
};

export function Checkbox({
  className,
  containerClassName,
  disabled,
  error,
  id,
  label,
  name,
  ...props
}: CheckboxProps) {
  const checkboxId = id ?? name;
  const errorMessage = useFieldError(error);

  return (
    <div className={containerClassName}>
      <label
        htmlFor={checkboxId}
        className={cn(
          'group flex items-center gap-2 text-xs font-medium text-white',
          disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
        )}
      >
        <span className="relative flex size-4 shrink-0 items-center justify-center rounded-sm border-[3px] border-primary bg-transparent transition group-has-checked:bg-primary">
          <input
            {...props}
            type="checkbox"
            id={checkboxId}
            name={name}
            disabled={disabled}
            className={cn(
              'absolute inset-0 m-0 size-full cursor-pointer appearance-none opacity-0',
              className,
            )}
          />
          <span className="material-symbols-rounded text-xs! font-bold text-black opacity-0 transition group-has-checked:opacity-100">
            check
          </span>
        </span>
        {label}
      </label>
      {errorMessage && <p className="mt-2 text-xs text-error">{errorMessage}</p>}
    </div>
  );
}
