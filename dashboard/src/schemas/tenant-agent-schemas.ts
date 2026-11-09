import { z } from 'zod';

export const TenantAgentFormSchema = z.object({
  description: z.string().optional(),
  name: z.string().min(1, 'validation.nameRequired'),
  ownerId: z.string().optional(),
});

export type TenantAgentFormInput = z.infer<typeof TenantAgentFormSchema>;
