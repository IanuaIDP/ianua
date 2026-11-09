import type { PasswordPolicy } from '@/types/auth-config';

/** A translator for the `auth.passwordPolicy` messages, plus the language for joining the list. */
export type PasswordHintTranslation = {
  locale: string;
  t: (key: string, values?: Record<string, number | string>) => string;
};

const DEFAULT_REQUIREMENT_LABELS = {
  digit: 'a digit',
  lowercase: 'a lowercase letter',
  special: 'a special character',
  uppercase: 'an uppercase letter',
};

/**
 * The requirements as one sentence, for example "At least 12 characters, an
 * uppercase letter, and a digit". Without `translation` it is English, which
 * the screens that are not translated yet rely on.
 */
export function getPasswordRequirementsHint(
  policy: PasswordPolicy,
  translation?: PasswordHintTranslation,
): string {
  const labelOf = (key: keyof typeof DEFAULT_REQUIREMENT_LABELS) =>
    translation ? translation.t(key) : DEFAULT_REQUIREMENT_LABELS[key];
  const parts: string[] = [];

  if (policy.require.uppercase) {
    parts.push(labelOf('uppercase'));
  }

  if (policy.require.lowercase) {
    parts.push(labelOf('lowercase'));
  }

  if (policy.require.digit) {
    parts.push(labelOf('digit'));
  }

  if (policy.require.special) {
    parts.push(labelOf('special'));
  }

  const requirements = new Intl.ListFormat(translation?.locale ?? 'en', {
    style: 'long',
    type: 'conjunction',
  }).format(parts);

  if (!translation) {
    return `At least ${policy.minLength} characters${parts.length > 0 ? `, ${requirements}` : ''}`;
  }

  return parts.length > 0
    ? translation.t('hintWithRequirements', { minLength: policy.minLength, requirements })
    : translation.t('hint', { minLength: policy.minLength });
}

const SPECIAL_CHARACTERS = '!@#$%^&*()-_=+[]{};:,.?';
const UPPERCASE_CHARACTERS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWERCASE_CHARACTERS = 'abcdefghjkmnpqrstuvwxyz';
const DIGIT_CHARACTERS = '23456789';

function randomFrom(characters: string): string {
  const index = window.crypto.getRandomValues(new Uint32Array(1))[0] % characters.length;

  return characters[index];
}

function shuffle<T>(items: T[]): T[] {
  const shuffled = [...items];

  for (let i = shuffled.length - 1; i > 0; i -= 1) {
    const j = window.crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);

    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }

  return shuffled;
}

export function generatePasswordForPolicy(policy: PasswordPolicy): string {
  const required: string[] = [];

  if (policy.require.uppercase) {
    required.push(randomFrom(UPPERCASE_CHARACTERS));
  }

  if (policy.require.lowercase) {
    required.push(randomFrom(LOWERCASE_CHARACTERS));
  }

  if (policy.require.digit) {
    required.push(randomFrom(DIGIT_CHARACTERS));
  }

  if (policy.require.special) {
    required.push(randomFrom(SPECIAL_CHARACTERS));
  }

  const allCharacters = UPPERCASE_CHARACTERS + LOWERCASE_CHARACTERS + DIGIT_CHARACTERS;
  const targetLength = Math.max(policy.minLength, required.length);

  while (required.length < targetLength) {
    required.push(randomFrom(allCharacters));
  }

  return shuffle(required).join('');
}
