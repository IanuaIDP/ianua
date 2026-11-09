import { z } from 'zod';

export const FlowNodeFormSchema = z.object({
  agentId: z.string().min(1, 'validation.agentRequired'),
  approvalClasses: z.array(z.string()),
  askPastMicros: z.number().optional(),
  goal: z.string().min(1, 'validation.goalRequired'),
  maxSteps: z.number().min(1, 'validation.stepCapMin').max(20, 'validation.stepCapMax'),
  providerId: z.string().min(1, 'validation.providerRequired'),
  purpose: z.array(z.string()).min(1, 'validation.purposeRequired'),
  spendCapMicros: z.number().optional(),
  toolNames: z.array(z.string()),
});

export type FlowNodeFormInput = z.infer<typeof FlowNodeFormSchema>;

export const CreateFlowDetailsSchema = z.object({
  description: z.string().optional(),
  name: z.string().min(1, 'validation.flowNameRequired').max(100, 'validation.flowNameTooLong'),
});

export type CreateFlowDetailsInput = z.infer<typeof CreateFlowDetailsSchema>;
