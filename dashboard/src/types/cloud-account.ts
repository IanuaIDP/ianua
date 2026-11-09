export type CloudProviderId = 'aws' | 'gcp' | 'azure' | 'digitalocean' | 'kubernetes';

export type CloudAccountState =
  'awaiting_credential' | 'awaiting_verification' | 'verified' | 'failed';

export type CloudAccountStatus = 'Pending' | 'PendingVerification' | 'Verified' | 'Failed';

export type CloudAccountAction = 'Reverify' | 'Disconnect';

export type CloudAccount = {
  account?: string;
  connected: string;
  failureReason?: string;
  provider: CloudProviderId;
  revocableByYou: boolean;
  status: CloudAccountStatus;
  usable: boolean;
  verified: string;
};

export type ConnectionInstructions = {
  consoleUrl?: string;
  externalId: string;
  provider: CloudProviderId;
  steps: string[];
};

export type CloudNetwork = {
  handle: string;
  name: string;
  region: string;
};

export type DeploymentRegionId =
  | 'UsEast1'
  | 'UsWest2'
  | 'CaCentral1'
  | 'EuWest1'
  | 'EuWest2'
  | 'EuWest3'
  | 'EuCentral1'
  | 'EuCentral2'
  | 'EuNorth1'
  | 'EuSouth1'
  | 'SaEast1'
  | 'ApSouth1'
  | 'ApNortheast1'
  | 'ApSoutheast1'
  | 'ApSoutheast2';

export type IsolationLevelId =
  'Shared' | 'DedicatedSchema' | 'DedicatedInstance' | 'DedicatedCluster';

export type ResidencyKind = 'platform' | 'customer_cloud' | 'customer_database';

export type TenantResidency = {
  dataResidency?: string;
  isolation: IsolationLevelId;
  kind: ResidencyKind;
  network?: string;
  networkPending: boolean;
  provider?: CloudProviderId;
  region?: string;
};
