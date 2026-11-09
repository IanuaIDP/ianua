import type { SelectOption } from '@/types/dashboard';
import type { CloudCredentialInput } from '@/schemas/cloud-schemas';
import type { CloudProviderId, DeploymentRegionId, ResidencyKind } from '@/types/cloud-account';

type CloudProviderMeta = {
  buildsNetworks: boolean;
  credentialKind: CloudCredentialInput['kind'];
  id: CloudProviderId;
  label: string;
  shortLabel: string;
};

export const CLOUD_PROVIDERS: CloudProviderMeta[] = [
  {
    buildsNetworks: true,
    credentialKind: 'aws_assume_role',
    id: 'aws',
    label: 'Amazon Web Services',
    shortLabel: 'AWS',
  },
  {
    buildsNetworks: true,
    credentialKind: 'gcp_service_account',
    id: 'gcp',
    label: 'Google Cloud',
    shortLabel: 'GCP',
  },
  {
    buildsNetworks: true,
    credentialKind: 'azure_service_principal',
    id: 'azure',
    label: 'Microsoft Azure',
    shortLabel: 'Azure',
  },
  {
    buildsNetworks: true,
    credentialKind: 'digitalocean_token',
    id: 'digitalocean',
    label: 'DigitalOcean',
    shortLabel: 'DigitalOcean',
  },
  {
    buildsNetworks: false,
    credentialKind: 'kubernetes_service_account',
    id: 'kubernetes',
    label: 'Your Kubernetes cluster',
    shortLabel: 'Kubernetes',
  },
];

export const CLOUD_PROVIDER_OPTIONS: SelectOption[] = CLOUD_PROVIDERS.map((provider) => ({
  label: provider.label,
  value: provider.id,
}));

export function getCloudProvider(id: CloudProviderId) {
  return CLOUD_PROVIDERS.find((provider) => provider.id === id) ?? CLOUD_PROVIDERS[0];
}

export function getCloudProviderLabel(id: CloudProviderId) {
  return getCloudProvider(id).label;
}

export const EMPTY_CLOUD_CREDENTIALS: Record<CloudProviderId, CloudCredentialInput> = {
  aws: { kind: 'aws_assume_role', roleArn: '' },
  azure: { clientId: '', directoryId: '', kind: 'azure_service_principal', secret: '' },
  digitalocean: { kind: 'digitalocean_token', token: '' },
  gcp: { clientEmail: '', key: '', kind: 'gcp_service_account' },
  kubernetes: {
    caCertificate: '',
    kind: 'kubernetes_service_account',
    server: '',
    token: '',
  },
};

type DeploymentRegionMeta = {
  id: DeploymentRegionId;
  jurisdiction: string;
  label: string;
  slug: string;
};

export const DEPLOYMENT_REGIONS: DeploymentRegionMeta[] = [
  { id: 'UsEast1', jurisdiction: 'United States', label: 'US East (Virginia)', slug: 'us-east-1' },
  { id: 'UsWest2', jurisdiction: 'United States', label: 'US West (Oregon)', slug: 'us-west-2' },
  {
    id: 'CaCentral1',
    jurisdiction: 'Canada',
    label: 'Canada Central (Montreal)',
    slug: 'ca-central-1',
  },
  {
    id: 'EuCentral1',
    jurisdiction: 'European Union',
    label: 'EU Central (Frankfurt)',
    slug: 'eu-central-1',
  },
  {
    id: 'EuWest1',
    jurisdiction: 'European Union',
    label: 'EU West (Ireland)',
    slug: 'eu-west-1',
  },
  { id: 'EuWest3', jurisdiction: 'European Union', label: 'EU West (Paris)', slug: 'eu-west-3' },
  {
    id: 'EuNorth1',
    jurisdiction: 'European Union',
    label: 'EU North (Stockholm)',
    slug: 'eu-north-1',
  },
  { id: 'EuSouth1', jurisdiction: 'European Union', label: 'EU South (Milan)', slug: 'eu-south-1' },
  {
    id: 'EuWest2',
    jurisdiction: 'United Kingdom',
    label: 'UK (London)',
    slug: 'eu-west-2',
  },
  {
    id: 'EuCentral2',
    jurisdiction: 'Switzerland',
    label: 'Switzerland (Zurich)',
    slug: 'eu-central-2',
  },
  { id: 'SaEast1', jurisdiction: 'Brazil', label: 'South America (São Paulo)', slug: 'sa-east-1' },
  { id: 'ApSouth1', jurisdiction: 'India', label: 'Asia Pacific (Mumbai)', slug: 'ap-south-1' },
  {
    id: 'ApNortheast1',
    jurisdiction: 'Japan',
    label: 'Asia Pacific (Tokyo)',
    slug: 'ap-northeast-1',
  },
  {
    id: 'ApSoutheast1',
    jurisdiction: 'Singapore',
    label: 'Asia Pacific (Singapore)',
    slug: 'ap-southeast-1',
  },
  {
    id: 'ApSoutheast2',
    jurisdiction: 'Australia',
    label: 'Asia Pacific (Sydney)',
    slug: 'ap-southeast-2',
  },
];

export function getRegionSlug(id: DeploymentRegionId) {
  return DEPLOYMENT_REGIONS.find((region) => region.id === id)?.slug ?? '';
}

export function getRegionLabel(slugOrId: string) {
  const region = DEPLOYMENT_REGIONS.find(
    (candidate) => candidate.slug === slugOrId || candidate.id === slugOrId,
  );

  return region ? region.label : slugOrId;
}

export const RESIDENCY_KIND_IDS: ResidencyKind[] = [
  'platform',
  'customer_cloud',
  'customer_database',
];
