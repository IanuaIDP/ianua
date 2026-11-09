'use client';

import { useCallback, useState } from 'react';
import { useTranslations } from 'next-intl';
import type { ReactNode } from 'react';
import {
  autoUpdate,
  flip,
  FloatingPortal,
  offset,
  shift,
  size,
  useClick,
  useDismiss,
  useFloating,
  useInteractions,
  useRole,
} from '@floating-ui/react';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

export type MultiSelectOption = {
  description?: string;
  label: string;
  value: string;
};

type MultiSelectProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  labelClassName?: string;
  onChange: (values: string[]) => void;
  options: MultiSelectOption[];
  placeholder?: string;
  value: string[];
};

export function MultiSelect({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  labelClassName,
  onChange,
  options,
  placeholder,
  value,
}: MultiSelectProps) {
  const t = useTranslations('common');
  const [isOpen, setIsOpen] = useState(false);
  const errorMessage = useFieldError(error);
  const selectedLabels = options
    .filter((option) => value.includes(option.value))
    .map((option) => option.label);

  const { context, floatingStyles, refs } = useFloating({
    middleware: [
      offset(6),
      flip(),
      shift({ padding: 8 }),
      size({
        apply({ rects, elements }) {
          elements.floating.style.width = `${rects.reference.width}px`;
        },
      }),
    ],
    onOpenChange: setIsOpen,
    open: isOpen,
    placement: 'bottom-start',
    whileElementsMounted: autoUpdate,
  });

  const click = useClick(context, { enabled: !disabled });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'listbox' });
  const { getFloatingProps, getReferenceProps } = useInteractions([click, dismiss, role]);
  const setReferenceNode = useCallback(
    (node: HTMLButtonElement | null) => {
      refs.setReference(node);
    },
    [refs],
  );
  const setFloatingNode = useCallback(
    (node: HTMLDivElement | null) => {
      refs.setFloating(node);
    },
    [refs],
  );

  function toggleOption(optionValue: string) {
    if (value.includes(optionValue)) {
      onChange(value.filter((current) => current !== optionValue));
      return;
    }

    onChange([...value, optionValue]);
  }

  return (
    <div className={cn('mb-6', containerClassName)}>
      {label && (
        <label className={cn('mb-2 block text-xs font-semibold text-white', labelClassName)}>
          {label}
        </label>
      )}
      <button
        ref={setReferenceNode}
        type="button"
        disabled={disabled}
        aria-expanded={isOpen}
        className={cn(
          'flex h-8 w-full items-center justify-between rounded-lg border bg-transparent px-2.5 text-left text-sm outline-none transition duration-200 enabled:hover:bg-hoverBg',
          selectedLabels.length > 0 ? 'text-white' : 'text-textGray',
          error ? 'border-error focus:border-error' : isOpen ? 'border-focus' : 'border-borderGray',
          disabled && 'cursor-not-allowed opacity-60',
          className,
        )}
        {...getReferenceProps()}
      >
        <span className="truncate">
          {selectedLabels.length > 0
            ? selectedLabels.join(', ')
            : (placeholder ?? t('selectPlaceholder'))}
        </span>
        <span className="material-symbols-rounded text-textGray" aria-hidden="true">
          arrow_drop_down
        </span>
      </button>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className="z-50 max-h-64 overflow-y-auto rounded-lg border border-borderGray bg-cardBg py-1.5 shadow-lg"
            {...getFloatingProps()}
          >
            {options.map((option) => {
              const isChecked = value.includes(option.value);

              return (
                <button
                  key={option.value}
                  type="button"
                  role="option"
                  aria-selected={isChecked}
                  onClick={() => toggleOption(option.value)}
                  className="flex w-full items-center gap-2.5 px-3 py-1.5 text-left text-sm text-white transition hover:bg-hoverBg"
                >
                  <span
                    className={cn(
                      'flex size-5 shrink-0 items-center justify-center rounded-md border-2 border-primary transition',
                      isChecked && 'bg-primary',
                    )}
                  >
                    {isChecked ? (
                      <span className="material-symbols-rounded text-sm! font-bold text-black">
                        check
                      </span>
                    ) : null}
                  </span>
                  <span className="min-w-0 truncate">
                    <span className="font-medium text-white">{option.label}</span>
                    {option.description ? (
                      <span className="text-textGray"> {option.description}</span>
                    ) : null}
                  </span>
                </button>
              );
            })}
          </div>
        </FloatingPortal>
      ) : null}

      {(errorMessage || hint) && (
        <p className={cn('mt-2 text-xs', errorMessage ? 'text-error' : 'text-textGray')}>
          {errorMessage || hint}
        </p>
      )}
    </div>
  );
}
