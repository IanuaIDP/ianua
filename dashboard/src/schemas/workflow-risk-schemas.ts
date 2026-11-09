import { z } from 'zod';

export const RISK_EFFECTS = ['undeclared', 'delete', 'configure', 'financial', 'admin'] as const;

export const RaiseRiskSchema = z.object({
  effect: z.enum(RISK_EFFECTS),
  integration: z.string().min(1, 'validation.integrationRequired'),
  operation: z.string().min(1, 'validation.operationRequired'),
});

export type RaiseRiskFormInput = z.infer<typeof RaiseRiskSchema>;
