import { z } from 'zod';

import { buildPasswordSchema } from '@/schemas/password-schema';
import type { PasswordPolicy } from '@/types/auth-config';

export function buildResetPasswordSchema(policy: PasswordPolicy, requirementsMessage?: string) {
  return z.object({
    password: buildPasswordSchema(policy, requirementsMessage),
  });
}

export type ResetPasswordInput = z.infer<ReturnType<typeof buildResetPasswordSchema>>;
