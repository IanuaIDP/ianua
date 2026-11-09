import { z } from 'zod';

function isHttpsUrl(value: string) {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export const StreamFormSchema = z.object({
  deliveryMethod: z.enum(['Push', 'Poll']),
  endpoint: z
    .string()
    .min(1, 'validation.endpointRequired')
    .refine(isHttpsUrl, 'validation.httpsUrl'),
  signalTypes: z.array(z.string()).min(1, 'validation.signalTypeRequired'),
});

export type StreamFormInput = z.infer<typeof StreamFormSchema>;
