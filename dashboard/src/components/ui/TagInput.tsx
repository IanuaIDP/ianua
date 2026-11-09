'use client';

import { useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';
import { useTranslations } from 'next-intl';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { cn } from '@/utils/cn';

type TagInputProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  maxLength?: number;
  onChange: (value: string[]) => void;
  placeholder?: string;
  value: string[];
};

export function TagInput({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  maxLength,
  onChange,
  placeholder,
  value,
}: TagInputProps) {
  const t = useTranslations('common');
  const [draft, setDraft] = useState('');
  const errorMessage = useFieldError(error);

  function commitDraft() {
    const tag = draft.trim();

    if (!tag || value.includes(tag)) {
      setDraft('');
      return;
    }

    onChange([...value, tag]);
    setDraft('');
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter' || event.key === ',') {
      // Enter inside a modal would otherwise submit the form rather than
      // finish the tag being typed.
      event.preventDefault();
      commitDraft();
      return;
    }

    if (event.key === 'Backspace' && !draft && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  }

  return (
    <div className={containerClassName}>
      {label ? <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p> : null}

      <div
        className={cn(
          'flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-borderGray px-2 py-1.5 transition focus-within:border-focus',
          disabled && 'pointer-events-none opacity-60',
          className,
        )}
      >
        {value.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded-full border border-focus/60 bg-focus/20 px-2 py-0.5 text-xs font-medium text-focus"
          >
            {tag}
            <button
              type="button"
              aria-label={`Remove ${tag}`}
              className="transition hover:text-white"
              onClick={() => onChange(value.filter((entry) => entry !== tag))}
            >
              <span className="material-symbols-rounded text-sm!">close</span>
            </button>
          </span>
        ))}

        <input
          type="text"
          value={draft}
          disabled={disabled}
          maxLength={maxLength}
          placeholder={value.length === 0 ? (placeholder ?? t('tagInputPlaceholder')) : ''}
          className="min-w-24 flex-1 bg-transparent text-xs font-medium text-white outline-none placeholder:text-textGray"
          onBlur={commitDraft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={handleKeyDown}
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
