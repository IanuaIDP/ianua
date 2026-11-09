'use client';

import type { InputHTMLAttributes } from 'react';
import { useTranslations } from 'next-intl';

import { cn } from '@/utils/cn';

type SearchInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  onClear?: () => void;
};

export function SearchInput({
  className,
  disabled,
  onClear,
  placeholder,
  value,
  ...props
}: SearchInputProps) {
  const t = useTranslations('common');
  const hasValue = Boolean(String(value ?? '').trim());

  return (
    <div className="relative mb-0 w-full">
      <span className="pointer-events-none absolute left-2.5 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray">
        <span className="material-symbols-rounded" aria-hidden="true">
          search
        </span>
      </span>
      <input
        {...props}
        autoComplete={props.autoComplete ?? 'off'}
        type="text"
        role="searchbox"
        disabled={disabled}
        placeholder={placeholder ?? t('searchPlaceholder')}
        value={value}
        className={cn(
          'h-8 w-full rounded-lg border border-borderGray bg-transparent pl-10 pr-8 text-sm text-white placeholder-textGray opacity-100 outline-none transition duration-200 enabled:hover:bg-hoverBg focus:border-focus disabled:border-borderGray disabled:bg-transparent disabled:text-textGray disabled:opacity-100 disabled:placeholder-textGray',
          className,
        )}
      />
      {hasValue && onClear ? (
        <button
          type="button"
          aria-label={t('clearSearch')}
          disabled={disabled}
          onClick={onClear}
          className="absolute right-2.5 top-1/2 flex size-5 -translate-y-1/2 items-center justify-center text-textGray transition enabled:hover:text-white disabled:pointer-events-none"
        >
          <span className="material-symbols-rounded" aria-hidden="true">
            close
          </span>
        </button>
      ) : null}
    </div>
  );
}
