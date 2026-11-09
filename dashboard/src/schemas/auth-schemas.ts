import { z } from 'zod';

import { buildPasswordSchema } from '@/schemas/password-schema';
import type { PasswordPolicy } from '@/types/auth-config';

/** The error messages of the auth forms, in the visitor's language (`useAuthValidationMessages`). */
export type AuthValidationMessages = {
  companyNameRequired: string;
  confirmPasswordRequired: string;
  displayNameRequired: string;
  emailInvalid: string;
  fullNameRequired: string;
  passwordRequired: string;
  passwordsDoNotMatch: string;
  termsRequired: string;
};

export function createSignUpSchema(
  messages: AuthValidationMessages,
  strongPasswordMessage: string,
) {
  const strongPasswordSchema = z
    .string()
    .min(12, strongPasswordMessage)
    .regex(/[A-Z]/, strongPasswordMessage)
    .regex(/[a-z]/, strongPasswordMessage)
    .regex(/\d/, strongPasswordMessage);

  return z
    .object({
      companyName: z.string().min(1, messages.companyNameRequired),
      fullName: z.string().min(1, messages.fullNameRequired),
      adminEmail: z.string().email(messages.emailInvalid),
      password: strongPasswordSchema,
      agreeToTerms: z.boolean(),
    })
    .refine((data) => data.agreeToTerms === true, {
      message: messages.termsRequired,
      path: ['agreeToTerms'],
    });
}

export function createLoginSchema(messages: AuthValidationMessages) {
  return z.object({
    email: z.string().email(messages.emailInvalid),
    password: z.string().min(1, messages.passwordRequired),
  });
}

export function createForgotPasswordSchema(messages: AuthValidationMessages) {
  return z.object({
    email: z.string().email(messages.emailInvalid),
  });
}

export function buildAcceptInviteSchema(
  policy: PasswordPolicy,
  messages: AuthValidationMessages,
  passwordRequirementsMessage: string,
) {
  return z
    .object({
      password: buildPasswordSchema(policy, passwordRequirementsMessage),
      confirmPassword: z.string().min(1, messages.confirmPasswordRequired),
      agreeToTerms: z.boolean().optional(),
    })
    .refine((data) => data.password === data.confirmPassword, {
      message: messages.passwordsDoNotMatch,
      path: ['confirmPassword'],
    });
}

export function buildTenantSignUpSchema(
  policy: PasswordPolicy,
  messages: AuthValidationMessages,
  passwordRequirementsMessage: string,
) {
  return z
    .object({
      displayName: z.string().trim().min(1, messages.displayNameRequired),
      email: z.string().email(messages.emailInvalid),
      password: buildPasswordSchema(policy, passwordRequirementsMessage),
      confirmPassword: z.string().min(1, messages.confirmPasswordRequired),
    })
    .refine((data) => data.password === data.confirmPassword, {
      message: messages.passwordsDoNotMatch,
      path: ['confirmPassword'],
    });
}

export type SignUpInput = z.infer<ReturnType<typeof createSignUpSchema>>;
export type LoginInput = z.infer<ReturnType<typeof createLoginSchema>>;
export type ForgotPasswordInput = z.infer<ReturnType<typeof createForgotPasswordSchema>>;
export type AcceptInviteInput = z.infer<ReturnType<typeof buildAcceptInviteSchema>>;
export type TenantSignUpInput = z.infer<ReturnType<typeof buildTenantSignUpSchema>>;
