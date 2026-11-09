import { z } from 'zod';

function isHttpsUrl(value: string) {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export const OAuthClientFormSchema = z
  .object({
    name: z.string().min(1, 'validation.nameRequired'),
    redirectUris: z.string().optional(),
  })
  .superRefine((value, context) => {
    const uris = (value.redirectUris ?? '')
      .split('\n')
      .map((uri) => uri.trim())
      .filter(Boolean);

    if (uris.some((uri) => !isHttpsUrl(uri))) {
      context.addIssue({
        code: 'custom',
        message: 'validation.redirectUrisInvalid',
        path: ['redirectUris'],
      });
    }
  });

export type OAuthClientFormInput = z.infer<typeof OAuthClientFormSchema>;
