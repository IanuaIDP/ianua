'use client';

import type { FieldError } from 'react-hook-form';

import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';

const VALIDATION_KEY_PREFIX = 'validation.';

/**
 * Turns a schema's message into text in the current language.
 *
 * Schemas name their messages with a `validation.<key>` key instead of text, so
 * they can stay plain constants. A message that needs a value carries it as a
 * query, as in `validation.actionKeyDuplicate?key=read`. Anything else, such as
 * a message that came from the backend, comes back as it is.
 */
export function useValidationText() {
  const t = useLooseTranslations('validation');

  return (message?: string) => {
    if (!message?.startsWith(VALIDATION_KEY_PREFIX)) {
      return message;
    }

    const [key, query = ''] = message.slice(VALIDATION_KEY_PREFIX.length).split('?');

    return t.has(key) ? t(key, Object.fromEntries(new URLSearchParams(query))) : message;
  };
}

/** The text of a form field's error in the current language. */
export function useFieldError(error?: FieldError | string) {
  const validationText = useValidationText();

  return validationText(typeof error === 'string' ? error : error?.message);
}
