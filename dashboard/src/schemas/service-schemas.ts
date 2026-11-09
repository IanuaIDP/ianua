import { z } from 'zod';

import { MAX_DISCOVERY_REFRESH_SECS, MIN_DISCOVERY_REFRESH_SECS } from '@/constants/service';

function isHttpUrl(value: string) {
  try {
    const protocol = new URL(value).protocol;
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

function isNonNegativeInteger(value: string) {
  return /^\d+$/.test(value.trim());
}

function isPositiveInteger(value: string) {
  return isNonNegativeInteger(value) && Number(value) >= 1;
}

const HealthCheckTimingsSchema = z.object({
  healthyThreshold: z.number(),
  intervalSecs: z.number(),
  panicThresholdPercent: z.number(),
  timeoutSecs: z.number(),
  unhealthyThreshold: z.number(),
});

const WeightedBackendFormSchema = z.object({
  url: z
    .string()
    .min(1, 'validation.backendUrlRequired')
    .refine(isHttpUrl, 'validation.urlInvalid'),
  weight: z.string().refine(isPositiveInteger, 'validation.weightInvalid'),
});

export const ServiceFormSchema = z
  .object({
    additionalBackends: z.array(WeightedBackendFormSchema),
    discoveryEnabled: z.boolean(),
    discoveryKind: z.enum(['address', 'srv']),
    discoveryName: z.string(),
    discoveryRefreshSecs: z.string().refine(isNonNegativeInteger, 'validation.refreshInvalid'),
    expectedAudience: z.string(),
    healthCheckEnabled: z.boolean(),
    healthCheckPath: z.string(),
    healthCheckTimings: HealthCheckTimingsSchema.nullable(),
    name: z.string().min(1, 'validation.nameRequired'),
    preserveHost: z.boolean(),
    requireClientCertificate: z.boolean(),
    stickySessionKind: z.enum(['None', 'UserId', 'ConsumerId', 'Cookie', 'Header', 'SourceIp']),
    stickySessionValue: z.string(),
    timeoutSecs: z.string().refine(isPositiveInteger, 'validation.timeoutInvalid'),
    upstreamUrl: z
      .string()
      .min(1, 'validation.upstreamRequired')
      .refine(isHttpUrl, 'validation.urlInvalid'),
  })
  .superRefine((values, ctx) => {
    if (values.discoveryEnabled && !values.discoveryName.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.discoveryNameRequired',
        path: ['discoveryName'],
      });
    }

    const refreshSecs = Number(values.discoveryRefreshSecs);
    if (
      values.discoveryEnabled &&
      (refreshSecs < MIN_DISCOVERY_REFRESH_SECS || refreshSecs > MAX_DISCOVERY_REFRESH_SECS)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `validation.refreshRange?min=${MIN_DISCOVERY_REFRESH_SECS}&max=${MAX_DISCOVERY_REFRESH_SECS}`,
        path: ['discoveryRefreshSecs'],
      });
    }

    if (values.healthCheckEnabled && !values.healthCheckPath.trim().startsWith('/')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.healthCheckPathInvalid',
        path: ['healthCheckPath'],
      });
    }

    if (
      (values.stickySessionKind === 'Cookie' || values.stickySessionKind === 'Header') &&
      !values.stickySessionValue.trim()
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          values.stickySessionKind === 'Cookie'
            ? 'validation.cookieNameRequired'
            : 'validation.headerNameRequired',
        path: ['stickySessionValue'],
      });
    }
  });

export type ServiceFormInput = z.infer<typeof ServiceFormSchema>;
