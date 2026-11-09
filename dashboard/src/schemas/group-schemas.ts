import { z } from 'zod';

export const GroupSchema = z.object({
  name: z.string().min(1, 'validation.groupNameRequired').max(100, 'validation.groupNameTooLong'),
  parentId: z.string(),
});

export type GroupInput = z.infer<typeof GroupSchema>;

export const AddGroupMemberSchema = z.object({
  id: z.string().min(1, 'validation.pickMember'),
  kind: z.enum(['user', 'org_user', 'agent', 'consumer']),
});

export type AddGroupMemberInput = z.infer<typeof AddGroupMemberSchema>;
