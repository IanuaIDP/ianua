'use client';

import type { ReactNode, TextareaHTMLAttributes } from 'react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  containerClassName?: string;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
};

export function Textarea({
  className,
  containerClassName,
  error,
  hint,
  id,
  label,
  name,
  ...props
}: TextareaProps) {
  const textareaId = id ?? name;
  const errorMessage = useFieldError(error);

  return (
    <div className={cn('mb-6', containerClassName)}>
      {label && (
        <label htmlFor={textareaId} className="mb-2 block text-xs font-semibold text-white">
          {label}
        </label>
      )}
      <textarea
        {...props}
        id={textareaId}
        name={name}
        className={cn(
          'w-full resize-none rounded-lg border border-borderGray bg-transparent px-2.5 py-2 text-sm text-white placeholder-textGray outline-none transition duration-200 hover:bg-hoverBg focus:border-focus',
          error && 'border-error focus:border-error',
          className,
        )}
      />
      {(errorMessage || hint) && (
        <p className={cn('text-xs', errorMessage ? 'text-error' : 'text-textGray')}>
          {errorMessage || hint}
        </p>
      )}
    </div>
  );
}
