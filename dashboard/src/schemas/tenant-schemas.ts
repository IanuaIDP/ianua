import { z } from 'zod';

const isolationLevelSchema = z.enum([
  'Shared',
  'DedicatedSchema',
  'DedicatedInstance',
  'DedicatedCluster',
]);

const deploymentRegionSchema = z.enum([
  'UsEast1',
  'UsWest2',
  'CaCentral1',
  'EuWest1',
  'EuWest2',
  'EuWest3',
  'EuCentral1',
  'EuCentral2',
  'EuNorth1',
  'EuSouth1',
  'SaEast1',
  'ApSouth1',
  'ApNortheast1',
  'ApSoutheast1',
  'ApSoutheast2',
]);

export const TenantResidencySchema = z
  .object({
    isolation: isolationLevelSchema,
    kind: z.enum(['platform', 'customer_cloud', 'customer_database']),
    network: z.string().optional(),
    provider: z.enum(['aws', 'gcp', 'azure', 'digitalocean', 'kubernetes']).optional(),
    region: deploymentRegionSchema.optional(),
  })
  .superRefine((residency, ctx) => {
    if (residency.kind === 'platform') {
      return;
    }

    if (residency.isolation === 'Shared' || residency.isolation === 'DedicatedSchema') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.ownDatabaseRequired',
        path: ['isolation'],
      });
    }

    if (residency.kind !== 'customer_cloud') {
      return;
    }

    if (!residency.provider) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.chooseCloud',
        path: ['provider'],
      });
    }

    if (!residency.region) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.chooseRegion',
        path: ['region'],
      });
    }
  });

export const CreateTenantSchema = z.object({
  contactEmail: z.string().email('validation.emailInvalid'),
  displayName: z.string().min(1, 'validation.nameRequired'),
  locale: z.string().min(1, 'validation.localeRequired'),
  residency: TenantResidencySchema,
  slug: z.string().min(1, 'validation.slugRequired'),
  timezone: z.string().min(1, 'validation.timezoneRequired'),
});

export const TenantSettingsGeneralSchema = z.object({
  contactEmail: z.string().email('validation.emailInvalid'),
  displayName: z.string().min(1, 'validation.displayNameRequired'),
  locale: z.string().min(1, 'validation.localeRequired'),
  timezone: z.string().min(1, 'validation.timezoneRequired'),
});

export type TenantResidencyInput = z.infer<typeof TenantResidencySchema>;
export type CreateTenantInput = z.infer<typeof CreateTenantSchema>;
export type TenantSettingsGeneralInput = z.infer<typeof TenantSettingsGeneralSchema>;
