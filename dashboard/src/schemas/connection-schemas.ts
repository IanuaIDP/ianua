import { z } from 'zod';

const controlCharacterPattern = /[\x00-\x1F\x7F]/;

function isHttpsUrl(value: string) {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export const AddConnectionSchema = z
  .object({
    allowedDomains: z.array(z.string()).min(1, 'validation.allowedDomainsRequired'),
    authorizationUrl: z.string().optional(),
    certificate: z.string().max(65536, 'validation.certificateTooLarge').optional(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    entityId: z.string().optional(),
    issuer: z.string().optional(),
    nameIdFormat: z.string().optional(),
    protocol: z.enum(['SAML', 'OIDC']),
    providerName: z
      .string()
      .min(1, 'validation.providerNameRequired')
      .max(100, 'validation.providerNameTooLong')
      .refine((value) => !controlCharacterPattern.test(value), {
        message: 'validation.providerNameInvalid',
      }),
    scopes: z.string().optional(),
    ssoUrl: z.string().optional(),
    tokenUrl: z.string().optional(),
  })
  .superRefine((value, context) => {
    if (value.protocol === 'SAML') {
      if (!value.entityId || !isHttpsUrl(value.entityId)) {
        context.addIssue({
          code: 'custom',
          message: 'validation.httpsUrl',
          path: ['entityId'],
        });
      }

      if (!value.ssoUrl || !isHttpsUrl(value.ssoUrl)) {
        context.addIssue({
          code: 'custom',
          message: 'validation.httpsUrl',
          path: ['ssoUrl'],
        });
      }

      if (!value.certificate?.trim()) {
        context.addIssue({
          code: 'custom',
          message: 'validation.certificateRequired',
          path: ['certificate'],
        });
      }

      if (!value.nameIdFormat?.trim()) {
        context.addIssue({
          code: 'custom',
          message: 'validation.nameIdFormatRequired',
          path: ['nameIdFormat'],
        });
      }

      return;
    }

    if (!value.issuer || !isHttpsUrl(value.issuer)) {
      context.addIssue({
        code: 'custom',
        message: 'validation.httpsUrl',
        path: ['issuer'],
      });
    }

    if (!value.authorizationUrl || !isHttpsUrl(value.authorizationUrl)) {
      context.addIssue({
        code: 'custom',
        message: 'validation.httpsUrl',
        path: ['authorizationUrl'],
      });
    }

    if (!value.tokenUrl || !isHttpsUrl(value.tokenUrl)) {
      context.addIssue({
        code: 'custom',
        message: 'validation.httpsUrl',
        path: ['tokenUrl'],
      });
    }

    if (!value.clientId?.trim()) {
      context.addIssue({
        code: 'custom',
        message: 'validation.clientIdRequired',
        path: ['clientId'],
      });
    }

    if (!value.clientSecret?.trim()) {
      context.addIssue({
        code: 'custom',
        message: 'validation.clientSecretRequired',
        path: ['clientSecret'],
      });
    }

    if (!value.scopes?.trim()) {
      context.addIssue({
        code: 'custom',
        message: 'validation.scopesRequired',
        path: ['scopes'],
      });
    }
  });

export type AddConnectionInput = z.infer<typeof AddConnectionSchema>;
