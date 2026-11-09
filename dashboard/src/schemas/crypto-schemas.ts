import { z } from 'zod';

export const RotateCryptoKeySchema = z.object({
  algorithm: z.enum(['RS256', 'ES256', 'EdDSA']),
});

export type RotateCryptoKeyInput = z.infer<typeof RotateCryptoKeySchema>;

export const PlanCryptoMigrationSchema = z.object({
  targetAlgorithm: z.enum(['RS256', 'ES256', 'EdDSA']),
});

export type PlanCryptoMigrationInput = z.infer<typeof PlanCryptoMigrationSchema>;

export const RollbackCryptoMigrationSchema = z.object({
  reason: z.string().min(1, 'validation.reasonRequired'),
});

export type RollbackCryptoMigrationInput = z.infer<typeof RollbackCryptoMigrationSchema>;
