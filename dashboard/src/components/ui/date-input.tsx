'use client';

import type { ComponentProps } from 'react';
import { useEffect, useRef, useState } from 'react';
import { format } from 'date-fns';
import { useTranslations } from 'next-intl';
import { DayPicker, type DateRange } from 'react-day-picker';

import { useDayPickerLocale } from '@/hooks/i18n/use-day-picker-locale';
import { cn } from '@/utils/cn';

type DateInputProps = Omit<ComponentProps<'button'>, 'onChange' | 'type' | 'value'> & {
  disableFutureDates?: boolean;
  onChange: (value: DateRange | undefined) => void;
  placeholder?: string;
  value?: DateRange;
};

function formatDateRange(value?: DateRange) {
  if (!value?.from) {
    return '';
  }

  if (!value.to) {
    return format(value.from, 'dd.MM.yyyy');
  }

  return `${format(value.from, 'dd.MM.yyyy')} - ${format(value.to, 'dd.MM.yyyy')}`;
}

export function DateInput({
  className,
  disableFutureDates = false,
  placeholder,
  value,
  onChange,
  ...props
}: DateInputProps) {
  const t = useTranslations('common');
  const dayPickerLocale = useDayPickerLocale();
  const [isOpen, setIsOpen] = useState(false);
  const [calendarMonth, setCalendarMonth] = useState(() => new Date());
  const containerRef = useRef<HTMLDivElement>(null);
  const label = formatDateRange(value);
  const selectedRange = value?.from ? value : undefined;

  function getInitialCalendarMonth() {
    return value?.from ?? value?.to ?? new Date();
  }

  function toggleCalendar() {
    setIsOpen((current) => {
      if (!current) {
        setCalendarMonth(getInitialCalendarMonth());
      }

      return !current;
    });
  }

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

  return (
    <div ref={containerRef} className="relative mb-0 w-full">
      <button
        type="button"
        className={cn(
          'flex h-8 w-full items-center justify-between rounded-lg border border-borderGray bg-transparent pl-2.5 pr-2.5 text-left text-sm text-white outline-none transition duration-200 hover:bg-hoverBg focus:border-focus',
          !label && 'text-textGray',
          className,
        )}
        onClick={toggleCalendar}
        {...props}
      >
        <span className="min-w-0 truncate">
          {label || (placeholder ?? t('dateRangePlaceholder'))}
        </span>
        <span className="material-symbols-rounded ml-2 shrink-0 text-textGray" aria-hidden="true">
          calendar_month
        </span>
      </button>

      {isOpen ? (
        <div className="absolute left-0 top-10 z-50 w-max overflow-hidden rounded-lg border border-borderGray bg-cardBg p-3 shadow-2xl shadow-black/60">
          <DayPicker
            locale={dayPickerLocale}
            mode="range"
            month={calendarMonth}
            onMonthChange={setCalendarMonth}
            selected={selectedRange}
            onSelect={(range) => {
              onChange(range);
              if (range?.from && range.to) {
                setIsOpen(false);
              }
            }}
            min={1}
            disabled={disableFutureDates ? { after: new Date() } : undefined}
            resetOnSelect
            numberOfMonths={2}
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
              range_start: 'rounded-l-md bg-primary text-black',
              range_middle: 'rounded-none bg-primary/20 text-white',
              range_end: 'rounded-r-md bg-primary text-black',
            }}
          />
        </div>
      ) : null}
    </div>
  );
}

export type { DateRange };
