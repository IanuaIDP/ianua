'use client';

import { useTranslations } from 'next-intl';

export type LooseTranslator = {
  (key: string, values?: Record<string, number | string>): string;
  has: (key: string) => boolean;
};

/**
 * A translator for keys that are built at run time, such as a message looked up
 * by a status or an action name. The typed translator cannot check those, so
 * the caller asks `has` first and falls back to the raw name.
 */
export function useLooseTranslations(namespace: string) {
  const t = useTranslations(namespace as never);

  return t as unknown as LooseTranslator;
}
