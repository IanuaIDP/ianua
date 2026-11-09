'use client';

import { useMemo, useState } from 'react';
import { useLocale, useTranslations } from 'next-intl';

import { Select } from '@/components/ui/Select';
import { ACTIVITY_DAY_OF_WEEK_IDS, ACTIVITY_LEVEL_COLOR_CLASSES } from '@/constants/activity';
import {
  buildCalendarWeeks,
  getMonthFormatter,
  getTooltipDateFormatter,
  type CalendarCell,
} from '@/lib/overview/activity';
import type { ActivityDay } from '@/types/activity';
import { cn } from '@/utils/cn';

type ActivityCalendarCardProps = {
  categories: string[];
  className?: string;
  days: ActivityDay[];
  isLoading?: boolean;
  onCategoryChange: (category: string) => void;
  selectedCategory: string;
};

function DayCell({ cell }: { cell: CalendarCell }) {
  const t = useTranslations('dashboard.overview.activity');
  const locale = useLocale();
  const [isHovered, setIsHovered] = useState(false);

  if (!cell.inRange) {
    return <div className="h-4 w-full max-w-8.25" />;
  }

  return (
    <div
      className="group/day relative w-full"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div
        className={cn(
          'h-4 w-full max-w-8.25 rounded-sm transition',
          ACTIVITY_LEVEL_COLOR_CLASSES[cell.level],
          isHovered && 'outline outline-offset-1 outline-white',
        )}
      />
      {isHovered ? (
        <div className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 whitespace-nowrap rounded-lg bg-white px-3 py-2 text-xs font-extrabold text-appBg shadow-lg">
          <span className="font-semibold">{getTooltipDateFormatter(locale).format(cell.date)}</span>
          <span className="ml-3 font-bold">{t('events', { count: cell.count })}</span>
        </div>
      ) : null}
    </div>
  );
}

export function ActivityCalendarCard({
  categories,
  className,
  days,
  isLoading = false,
  onCategoryChange,
  selectedCategory,
}: ActivityCalendarCardProps) {
  const t = useTranslations('dashboard.overview.activity');
  const locale = useLocale();
  const { weeks } = useMemo(
    () => buildCalendarWeeks(days, selectedCategory),
    [days, selectedCategory],
  );

  return (
    <section
      className={cn(
        'flex flex-col rounded-lg border border-borderGray bg-cardBg pt-2.75 px-4 pb-2.75',
        className,
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-white">{t('title')}</h2>
        {categories.length > 0 ? (
          <Select
            containerClassName="mb-0 w-44"
            options={categories.map((category) => ({ label: category, value: category }))}
            value={selectedCategory}
            onChange={onCategoryChange}
          />
        ) : null}
      </div>

      {isLoading || weeks.length === 0 ? (
        <div className="mt-4 flex h-32 items-center justify-center text-sm text-textGray">
          {isLoading ? t('loading') : t('empty')}
        </div>
      ) : (
        <div className="mt-4 flex gap-2">
          <div className="flex shrink-0 flex-col gap-1.25 pt-4.5 text-xs text-textGray">
            {ACTIVITY_DAY_OF_WEEK_IDS.map((id, index) => (
              <div key={index} className="flex h-4 items-center leading-none">
                {id ? t(`weekdays.${id}`) : ''}
              </div>
            ))}
          </div>

          <div className="min-w-0 flex-1">
            <div
              className="mb-1 grid gap-x-1.5"
              style={{ gridTemplateColumns: `repeat(${weeks.length}, minmax(0, 1fr))` }}
            >
              {weeks.map((week, weekIndex) => {
                const monthCell = week.find((cell) => cell.isFirstOfMonth && cell.inRange);

                return (
                  <div
                    key={weekIndex}
                    className="overflow-visible whitespace-nowrap text-xs text-textGray"
                  >
                    {monthCell ? getMonthFormatter(locale).format(monthCell.date) : ''}
                  </div>
                );
              })}
            </div>

            <div
              className="grid gap-x-1.5 gap-y-1.25"
              style={{
                gridAutoFlow: 'column',
                gridTemplateColumns: `repeat(${weeks.length}, minmax(0, 1fr))`,
                gridTemplateRows: 'repeat(7, auto)',
              }}
            >
              {weeks.flat().map((cell) => (
                <DayCell key={cell.dateKey} cell={cell} />
              ))}
            </div>

            <div className="mt-3 flex items-center justify-end gap-1.5 text-xs font-medium text-textGray">
              <span>{t('less')}</span>
              {ACTIVITY_LEVEL_COLOR_CLASSES.map((colorClass) => (
                <span key={colorClass} className={cn('h-4 w-6.5 rounded-sm', colorClass)} />
              ))}
              <span>{t('more')}</span>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
