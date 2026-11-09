'use client';

import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { format, parseISO } from 'date-fns';
import { useTranslations } from 'next-intl';
import { DayPicker } from 'react-day-picker';
import type { FieldError } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { useDayPickerLocale } from '@/hooks/i18n/use-day-picker-locale';
import { cn } from '@/utils/cn';

type DayInputProps = {
  className?: string;
  containerClassName?: string;
  disabled?: boolean;
  error?: FieldError | string;
  hint?: ReactNode;
  label?: string;
  onChange: (value: string) => void;
  placeholder?: string;
  /** Whether to also take a time of day, stored as an RFC 3339 timestamp. */
  withTime?: boolean;
  /** `YYYY-MM-DD`, or an RFC 3339 timestamp when `withTime`. Empty for unset. */
  value: string;
};

/**
 * One day, and optionally a time on it.
 *
 * Separate from [`DateInput`](./date-input.tsx), which selects a *range* for
 * filtering a listing. A custom field holds a single date, and the two cannot
 * share a value shape.
 *
 * The stored value is ISO on purpose: it is what the API accepts, and it is
 * what makes the column sort correctly as text.
 */
export function DayInput({
  className,
  containerClassName,
  disabled = false,
  error,
  hint,
  label,
  onChange,
  placeholder,
  value,
  withTime = false,
}: DayInputProps) {
  const t = useTranslations('common');
  const dayPickerLocale = useDayPickerLocale();
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const errorMessage = useFieldError(error);
  const selected = toDate(value);
  const [calendarMonth, setCalendarMonth] = useState(() => selected ?? new Date());
  const timeValue = selected && withTime ? format(selected, 'HH:mm') : '';

  useEffect(() => {
    function handlePointerDown(event: PointerEvent) {
      if (!containerRef.current?.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('pointerdown', handlePointerDown);

    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
    };
  }, []);

  function commit(day: Date, time: string) {
    if (!withTime) {
      onChange(format(day, 'yyyy-MM-dd'));
      setIsOpen(false);
      return;
    }

    const [hours, minutes] = time ? time.split(':') : ['00', '00'];
    const withClock = new Date(day);
    withClock.setHours(Number(hours), Number(minutes), 0, 0);
    onChange(withClock.toISOString());
  }

  return (
    <div className={containerClassName}>
      {label ? <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p> : null}

      <div ref={containerRef} className="relative w-full">
        <button
          type="button"
          disabled={disabled}
          className={cn(
            'flex h-9 w-full items-center justify-between rounded-lg border border-borderGray bg-transparent px-2.5 text-left text-xs font-medium text-white outline-none transition duration-200 hover:bg-hoverBg focus:border-focus disabled:pointer-events-none disabled:opacity-60',
            !selected && 'text-textGray',
            className,
          )}
          onClick={() => {
            setCalendarMonth(selected ?? new Date());
            setIsOpen((current) => !current);
          }}
        >
          <span className="min-w-0 truncate">
            {selected
              ? format(selected, withTime ? 'dd.MM.yyyy HH:mm' : 'dd.MM.yyyy')
              : (placeholder ?? t('datePlaceholder'))}
          </span>
          <span className="material-symbols-rounded ml-2 shrink-0 text-textGray" aria-hidden="true">
            calendar_month
          </span>
        </button>

        {isOpen ? (
          <div className="absolute left-0 top-11 z-50 w-max overflow-hidden rounded-lg border border-borderGray bg-cardBg p-3 shadow-2xl shadow-black/60">
            <DayPicker
              locale={dayPickerLocale}
              mode="single"
              month={calendarMonth}
              selected={selected}
              onMonthChange={setCalendarMonth}
              onSelect={(day) => {
                if (day) {
                  commit(day, timeValue);
                }
              }}
              classNames={{
                root: 'relative text-white',
                months: 'flex gap-4 rounded-md bg-cardBg',
                month: 'w-64 space-y-2',
                month_caption: 'flex h-8 items-center justify-center text-sm font-semibold',
                nav: 'absolute right-3 top-3 flex items-center gap-1',
                button_previous:
                  'flex size-7 items-center justify-center rounded-md text-textGray hover:bg-hoverBg hover:text-white',
                button_next:
                  'flex size-7 items-center justify-center rounded-md text-textGray hover:bg-hoverBg hover:text-white',
                chevron: 'size-4 fill-current',
                month_grid: 'w-full border-separate border-spacing-1',
                weekdays: 'text-textGray',
                weekday: 'size-8 text-center text-xs font-semibold',
                day: 'size-8 p-0 text-center text-sm',
                day_button:
                  'flex size-8 items-center justify-center rounded-md transition disabled:cursor-default disabled:text-textGray hover:bg-primary disabled:hover:bg-transparent',
                outside: 'text-textGray/50',
                hidden: 'invisible bg-transparent! text-transparent!',
                disabled: 'pointer-events-none text-textGray opacity-100',
                selected: 'bg-primary text-black hover:bg-primary',
              }}
            />

            {withTime ? (
              <div className="mt-2 flex items-center gap-2 border-t border-borderGray pt-2">
                <span className="text-xs font-medium text-textGray">{t('time')}</span>
                <input
                  type="time"
                  value={timeValue}
                  className="h-8 flex-1 rounded-lg border border-borderGray bg-transparent px-2 text-xs font-medium text-white outline-none transition focus:border-focus"
                  onChange={(event) => commit(selected ?? new Date(), event.target.value)}
                />
                <button
                  type="button"
                  className="text-xs font-semibold text-focus transition hover:text-focus/80"
                  onClick={() => setIsOpen(false)}
                >
                  Done
                </button>
              </div>
            ) : null}
          </div>
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

/** Reads the stored ISO value, tolerating the half-written state of a form. */
function toDate(value: string) {
  if (!value) {
    return undefined;
  }

  try {
    const parsed = parseISO(value);

    return Number.isNaN(parsed.getTime()) ? undefined : parsed;
  } catch {
    return undefined;
  }
}
