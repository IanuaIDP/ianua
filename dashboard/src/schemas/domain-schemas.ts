import { z } from 'zod';

export const AddDomainSchema = z.object({
  domain: z.string().min(1, 'validation.domainRequired'),
  connection: z.enum(['SelfManaged', 'Delegated']),
});

export type AddDomainInput = z.infer<typeof AddDomainSchema>;
