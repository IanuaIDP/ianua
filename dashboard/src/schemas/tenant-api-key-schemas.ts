import { format } from 'date-fns';
import { z } from 'zod';

export const CreateTenantApiKeySchema = z.object({
  name: z.string().min(1, 'validation.nameRequired'),
  scopes: z.array(z.string()).min(1, 'validation.permissionRequired'),
  endsOn: z
    .string()
    .refine((day) => !day || day >= format(new Date(), 'yyyy-MM-dd'), 'validation.endDateInPast'),
});

export type CreateTenantApiKeyInput = z.infer<typeof CreateTenantApiKeySchema>;
