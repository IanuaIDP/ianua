import { z } from 'zod';

import { buildPasswordSchema } from '@/schemas/password-schema';
import type { PasswordPolicy } from '@/types/auth-config';

export function buildAddTenantUserSchema(policy: PasswordPolicy, requirementsMessage?: string) {
  const passwordSchema = buildPasswordSchema(policy, requirementsMessage);

  return z
    .object({
      autoVerify: z.boolean(),
      email: z.string().email('validation.emailInvalid'),
      fullName: z.string().min(1, 'validation.fullNameRequired'),
      mode: z.enum(['invite', 'create']),
      password: z.string().optional(),
      roleIds: z.array(z.string()).min(1, 'validation.roleRequired'),
    })
    .superRefine((value, context) => {
      if (value.mode !== 'create') {
        return;
      }

      const result = passwordSchema.safeParse(value.password);

      if (!result.success) {
        for (const issue of result.error.issues) {
          context.addIssue({
            ...issue,
            path: ['password'],
          });
        }
      }
    });
}

export type AddTenantUserInput = z.infer<ReturnType<typeof buildAddTenantUserSchema>>;
