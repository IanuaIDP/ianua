import { z } from 'zod';

export const AwsCredentialSchema = z.object({
  kind: z.literal('aws_assume_role'),
  roleArn: z
    .string()
    .min(1, 'validation.roleArnRequired')
    .regex(/^arn:aws[a-z-]*:iam::\d{12}:role\/.+$/, 'validation.roleArnFormat'),
});

export const GcpCredentialSchema = z.object({
  clientEmail: z.string().email('validation.serviceAccountEmail'),
  key: z
    .string()
    .min(1, 'validation.serviceAccountKeyRequired')
    .refine((value) => {
      try {
        return typeof JSON.parse(value) === 'object';
      } catch {
        return false;
      }
    }, 'validation.serviceAccountKeyJson'),
  kind: z.literal('gcp_service_account'),
});

export const AzureCredentialSchema = z.object({
  clientId: z.string().min(1, 'validation.applicationIdRequired'),
  directoryId: z.string().min(1, 'validation.directoryIdRequired'),
  kind: z.literal('azure_service_principal'),
  secret: z.string().min(1, 'validation.clientSecretRequired'),
});

export const DigitalOceanCredentialSchema = z.object({
  kind: z.literal('digitalocean_token'),
  token: z.string().min(1, 'validation.accessTokenRequired'),
});

export const KubernetesCredentialSchema = z.object({
  caCertificate: z
    .string()
    .min(1, 'validation.caCertificateRequired')
    .refine(
      (value) => value.includes('-----BEGIN CERTIFICATE-----'),
      'validation.caCertificatePem',
    ),
  kind: z.literal('kubernetes_service_account'),
  server: z
    .string()
    .min(1, 'validation.serverRequired')
    .url('validation.serverUrl')
    .refine((value) => value.startsWith('https://'), 'validation.serverHttps'),
  token: z.string().min(1, 'validation.serviceAccountTokenRequired'),
});

export const CloudCredentialSchema = z.discriminatedUnion('kind', [
  AwsCredentialSchema,
  GcpCredentialSchema,
  AzureCredentialSchema,
  DigitalOceanCredentialSchema,
  KubernetesCredentialSchema,
]);

export type AwsCredentialInput = z.infer<typeof AwsCredentialSchema>;
export type GcpCredentialInput = z.infer<typeof GcpCredentialSchema>;
export type AzureCredentialInput = z.infer<typeof AzureCredentialSchema>;
export type DigitalOceanCredentialInput = z.infer<typeof DigitalOceanCredentialSchema>;
export type KubernetesCredentialInput = z.infer<typeof KubernetesCredentialSchema>;
export type CloudCredentialInput = z.infer<typeof CloudCredentialSchema>;
