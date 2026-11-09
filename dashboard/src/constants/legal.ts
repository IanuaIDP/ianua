export const LEGAL_CONTACT_EMAIL = 'legal@ianua.io';

// Shown as is in every language, in the format used by the messages.
export const LEGAL_LAST_UPDATED = '06.08.2026';

// The text of each item is in messages/<language>.json under `legal`.
export const PRIVACY_DATA_COLLECTED_IDS = [
  'email',
  'displayName',
  'password',
  'mfaSecret',
  'sessions',
  'audit',
] as const;

export const PRIVACY_DATA_RECIPIENT_IDS = ['hosting', 'email', 'monitoring'] as const;

export const TERMS_PROHIBITED_USE_IDS = ['sensitive', 'illegal', 'attack', 'abuse'] as const;
