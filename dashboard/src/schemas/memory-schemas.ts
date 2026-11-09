import { z } from 'zod';

export const CreateMemorySchema = z.object({
  clearance: z.enum(['public', 'internal', 'confidential', 'restricted']),
  name: z.string().trim().min(1, 'validation.nameRequired'),
  providerId: z.string(),
});

export type CreateMemoryFormInput = z.infer<typeof CreateMemorySchema>;

export const EmbeddingModelSchema = z.object({
  embeddingModel: z.string().trim(),
});

export type EmbeddingModelFormInput = z.infer<typeof EmbeddingModelSchema>;
