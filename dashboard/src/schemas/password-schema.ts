import { z } from 'zod';

import type { PasswordPolicy } from '@/types/auth-config';
import { getPasswordRequirementsHint } from '@/utils/password-policy';

/** `requirementsMessage` is the error shown when a rule fails; English by default. */
export function buildPasswordSchema(policy: PasswordPolicy, requirementsMessage?: string) {
  const message = requirementsMessage ?? getPasswordRequirementsHint(policy);
  let schema = z.string().min(policy.minLength, message);

  if (policy.require.uppercase) {
    schema = schema.regex(/[A-Z]/, message);
  }

  if (policy.require.lowercase) {
    schema = schema.regex(/[a-z]/, message);
  }

  if (policy.require.digit) {
    schema = schema.regex(/\d/, message);
  }

  if (policy.require.special) {
    schema = schema.regex(/[^A-Za-z0-9]/, message);
  }

  return schema;
}
