import { z } from 'zod';

function isValidUrl(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export const ConnectModelProviderSchema = z.object({
  apiKey: z.string().optional(),
  endpoint: z
    .string()
    .min(1, 'validation.endpointRequired')
    .refine(isValidUrl, { message: 'validation.urlInvalid' }),
  kind: z.enum(['self_hosted', 'openai', 'anthropic']),
  model: z.string().min(1, 'validation.modelRequired'),
  name: z.string().min(1, 'validation.nameRequired'),
});

export type ConnectModelProviderInput = z.infer<typeof ConnectModelProviderSchema>;
