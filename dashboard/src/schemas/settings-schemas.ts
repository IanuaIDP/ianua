import { z } from 'zod';

import { buildPasswordSchema } from '@/schemas/password-schema';
import type { PasswordPolicy } from '@/types/auth-config';

export const OrganizationSettingsGeneralSchema = z.object({
  contactEmail: z.string().email('validation.emailInvalid'),
  displayName: z.string().min(1, 'validation.displayNameRequired'),
  name: z.string().min(1, 'validation.nameRequired'),
  urlSlug: z.string(),
});

export const AccountSettingsFullNameSchema = z.object({
  fullName: z.string().min(1, 'validation.fullNameRequired').max(100, 'validation.fullNameTooLong'),
});

export const AccountSettingsEmailSchema = z.object({
  email: z.string().email('validation.emailInvalid'),
});

export function buildAccountSettingsPasswordSchema(
  policy: PasswordPolicy,
  requirementsMessage?: string,
) {
  return z
    .object({
      confirmNewPassword: z.string().min(1, 'validation.confirmNewPasswordRequired'),
      currentPassword: z.string().min(1, 'validation.currentPasswordRequired'),
      newPassword: buildPasswordSchema(policy, requirementsMessage),
    })
    .refine((data) => data.newPassword === data.confirmNewPassword, {
      message: 'validation.passwordsDoNotMatch',
      path: ['confirmNewPassword'],
    });
}

export const CreateApiKeySchema = z.object({
  expiresAt: z.string().optional(),
  name: z.string().min(1, 'validation.nameRequired'),
  scopes: z.array(z.string()).min(1, 'validation.permissionRequired'),
});

export type OrganizationSettingsInput = z.infer<typeof OrganizationSettingsGeneralSchema>;
export type AccountSettingsFullNameInput = z.infer<typeof AccountSettingsFullNameSchema>;
export type AccountSettingsEmailInput = z.infer<typeof AccountSettingsEmailSchema>;
export type AccountSettingsPasswordInput = z.infer<
  ReturnType<typeof buildAccountSettingsPasswordSchema>
>;
export type CreateApiKeyInput = z.infer<typeof CreateApiKeySchema>;
