import { z } from 'zod';

const publicKeySchema = z
  .string()
  .trim()
  .min(1, 'validation.publicKeyRequired')
  .refine((value) => value.startsWith('-----BEGIN PUBLIC KEY-----'), {
    message: 'validation.publicKeyFormat',
  });

export const RotateCredentialSchema = z.object({
  algorithm: z.enum(['EdDSA', 'ES256', 'RS256']),
  publicKey: publicKeySchema,
});

export type RotateCredentialInput = z.infer<typeof RotateCredentialSchema>;

export const CreateCredentialSchema = RotateCredentialSchema.extend({
  expiresInSeconds: z.string().optional(),
});

export type CreateCredentialInput = z.infer<typeof CreateCredentialSchema>;

export const EditAttestationPolicySchema = z.object({
  methods: z
    .array(z.enum(['spiffe', 'aws', 'gcp', 'tpm']))
    .min(1, 'validation.attestationMethodRequired'),
  reattestIntervalSeconds: z.string().min(1, 'validation.reattestIntervalRequired'),
  allowedOrigins: z.array(z.string()).min(1, 'validation.originRequired'),
});

export type EditAttestationPolicyInput = z.infer<typeof EditAttestationPolicySchema>;
