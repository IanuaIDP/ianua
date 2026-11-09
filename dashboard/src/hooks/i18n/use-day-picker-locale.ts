import { useLocale } from 'next-intl';
import { enUS, uk } from 'react-day-picker/locale';

/** The calendar's own wording (month and weekday names, first day of the week) for the current language. */
export function useDayPickerLocale() {
  return useLocale() === 'uk' ? uk : enUS;
}
