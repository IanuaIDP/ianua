import { z } from 'zod';

export const StartRunFormSchema = z.object({
  approvalClasses: z.array(z.string()),
  delegationId: z.string(),
  goal: z.string().min(1, 'validation.goalRequired'),
  maxSteps: z.number().min(1, 'validation.stepLimitMin').max(20, 'validation.stepLimitMax'),
  providerId: z.string().min(1, 'validation.providerRequired'),
  purpose: z.array(z.string()).min(1, 'validation.purposeRequired'),
});

export type StartRunFormInput = z.infer<typeof StartRunFormSchema>;
