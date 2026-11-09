import type { AppLocale } from '@/i18n/config';
import type en from '../../messages/en.json';

// English is the source of truth: a key missing from it is a type error, and
// the Ukrainian file must mirror its shape (checked by `npm run check-messages`).
declare module 'next-intl' {
  interface AppConfig {
    Locale: AppLocale;
    Messages: typeof en;
  }
}
