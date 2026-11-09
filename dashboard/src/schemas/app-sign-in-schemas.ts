import { z } from 'zod';

const PATH_MESSAGE = 'validation.signInPathInvalid';

/// Mirrors the server's rules closely enough to catch typos before saving;
/// the server holds the final word.
function isSignInPath(value: string) {
  if (value === '') {
    return true;
  }
  return (
    /^\/([A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*)?$/.test(value) && !/(^|\/)\.{1,2}(\/|$)/.test(value)
  );
}

const OptionalPath = z.string().trim().refine(isSignInPath, PATH_MESSAGE);

export const AppSignInFormSchema = z
  .object({
    acceptsAppSignInOf: z.string(),
    afterSignIn: OptionalPath,
    cookieHosts: z.array(z.string()),
    deliveryKind: z.enum(['same_host', 'own_cookie', 'tokens']),
    enabled: z.boolean(),
    hosts: z.array(z.string()),
    paths: z.object({
      login: OptionalPath,
      logout: OptionalPath,
      mfa: OptionalPath,
      signup: OptionalPath,
      verify: OptionalPath,
    }),
    prefix: OptionalPath,
    signedOutBrowsers: z.enum(['refuse', 'redirect']),
  })
  .superRefine((value, ctx) => {
    if (value.enabled && value.hosts.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.signInHostsRequired',
        path: ['hosts'],
      });
    }
    if (
      !value.enabled &&
      value.acceptsAppSignInOf &&
      value.deliveryKind === 'own_cookie' &&
      value.cookieHosts.length === 0
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.cookieHostsRequired',
        path: ['cookieHosts'],
      });
    }
    if (value.enabled && value.prefix === '/') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.prefixNotRoot',
        path: ['prefix'],
      });
    }
  });

export type AppSignInFormInput = z.infer<typeof AppSignInFormSchema>;
