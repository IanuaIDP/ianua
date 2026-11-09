import { z } from 'zod';

export const CreateRoleSchema = z.object({
  name: z.string().min(1, 'validation.roleNameRequired'),
  permissions: z.array(z.record(z.string(), z.string())).min(1, 'validation.permissionRequired'),
});

export type CreateRoleInput = z.infer<typeof CreateRoleSchema>;
