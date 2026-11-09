import { z } from 'zod';

export const MtlsConfigSchema = z.object({
  mode: z.enum(['Disabled', 'Optional', 'Required']),
  trustedCaCertsText: z.string(),
});

export type MtlsConfigInput = z.infer<typeof MtlsConfigSchema>;
