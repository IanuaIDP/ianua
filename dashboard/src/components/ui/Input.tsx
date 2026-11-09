'use client';

import type { InputHTMLAttributes, ReactNode } from 'react';
import { useState } from 'react';
import { useTranslations } from 'next-intl';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  label?: ReactNode;
  error?: FieldError | string;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  rightAction?: ReactNode;
  hint?: ReactNode;
  containerClassName?: string;
  isPasswordVisible?: boolean;
  onPasswordVisibilityChange?: (isVisible: boolean) => void;
};

export function Input({
  label,
  error,
  leftIcon,
  rightAction,
  rightIcon,
  hint,
  isPasswordVisible: controlledPasswordVisible,
  className,
  containerClassName,
  id,
  name,
  onPasswordVisibilityChange,
  type,
  ...props
}: InputProps) {
  const t = useTranslations('common');
  const [uncontrolledPasswordVisible, setUncontrolledPasswordVisible] = useState(false);

  const inputId = id ?? name;
  const errorMessage = useFieldError(error);
  const isPassword = type === 'password';
  const isDisabled = Boolean(props.disabled);
  const isPasswordVisible = controlledPasswordVisible ?? uncontrolledPasswordVisible;
  const hasRightAction = Boolean(rightAction);
  const hasRightIcon = Boolean(rightIcon || isPassword || hasRightAction);
  const hasPasswordStatusIcon = Boolean(isPassword && rightIcon);
  const inputType = isPassword && isPasswordVisible ? 'text' : type;

  function handlePasswordVisibilityToggle() {
    const nextValue = !isPasswordVisible;

    if (controlledPasswordVisible === undefined) {
      setUncontrolledPasswordVisible(nextValue);
    }

    onPasswordVisibilityChange?.(nextValue);
  }

  const inputClasses = cn(
    'h-8 w-full rounded-lg border bg-transparent text-sm text-white placeholder-textGray opacity-100 outline-none transition duration-200 enabled:hover:bg-hoverBg disabled:border-borderGray disabled:bg-hoverBg/60 disabled:text-textGray disabled:opacity-100 disabled:placeholder-textGray',
    leftIcon ? 'pl-10' : 'pl-2.5',
    hasRightAction ? 'pr-40' : hasPasswordStatusIcon ? 'pr-14' : hasRightIcon ? 'pr-8' : 'pr-2.5',
    error ? 'border-error focus:border-error' : 'border-borderGray focus:border-focus',
    type === 'number' &&
      '[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none',
    className,
  );

  return (
    <div className={cn('mb-6', containerClassName)}>
      {label && (
        <label
          htmlFor={inputId}
          className={cn(
            'mb-2 block text-xs font-semibold tracking-normal',
            isDisabled ? 'text-textGray' : 'text-white',
          )}
        >
          {label}
        </label>
      )}
      <div className="relative">
        {leftIcon && (
          <span className="pointer-events-none absolute left-2.5 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray">
            {leftIcon}
          </span>
        )}
        <input
          {...props}
          autoComplete={props.autoComplete ?? 'off'}
          id={inputId}
          name={name}
          type={inputType}
          className={inputClasses}
        />
        {isPassword ? (
          <>
            {rightIcon && (
              <span className="pointer-events-none absolute right-8 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray">
                {rightIcon}
              </span>
            )}
            <button
              type="button"
              aria-label={isPasswordVisible ? t('hidePassword') : t('showPassword')}
              disabled={isDisabled}
              onClick={handlePasswordVisibilityToggle}
              className={cn(
                'absolute top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray transition hover:text-white disabled:pointer-events-none',
                hasRightAction ? 'right-32' : 'right-2.5',
              )}
            >
              <span className="material-symbols-rounded">
                {isPasswordVisible ? 'visibility_off' : 'visibility'}
              </span>
            </button>
            {hasRightAction ? (
              <span
                className="absolute right-29 top-1/2 h-5 w-px -translate-y-1/2 bg-borderGray"
                aria-hidden="true"
              />
            ) : null}
          </>
        ) : rightIcon ? (
          <span className="pointer-events-none absolute right-2.5 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray">
            {rightIcon}
          </span>
        ) : null}
        {rightAction ? (
          <span className="absolute right-3 top-1/2 flex h-6 -translate-y-1/2 items-center">
            {rightAction}
          </span>
        ) : null}
      </div>
      {(errorMessage || hint) && (
        <p className={cn('text-xs mt-2', errorMessage ? 'text-error' : 'text-textGray')}>
          {errorMessage || hint}
        </p>
      )}
    </div>
  );
}
