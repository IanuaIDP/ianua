export type SigningAlgorithm = 'RS256' | 'ES256' | 'EdDSA';

export type CryptoKeyStatus = 'Active' | 'Rotated' | 'Revoked';

export type CryptoKeyAction = 'Revoke';

export type CryptoMigrationStatus =
  'Planned' | 'InProgress' | 'Validating' | 'Completed' | 'RolledBack' | 'Cancelled';

export type CryptoMigrationAction = 'Cancel' | 'Start' | 'Promote' | 'Complete' | 'Rollback';

export type CryptoKey = {
  algorithm: SigningAlgorithm;
  created: string;
  expires: string;
  id: string;
  status: CryptoKeyStatus;
};

export type CryptoMigration = {
  created: string;
  sourceAlgorithm: SigningAlgorithm;
  sourceKeyId: string;
  status: CryptoMigrationStatus;
  targetAlgorithm: SigningAlgorithm;
  targetKeyId: string | null;
  updated: string;
};

export type CryptoJwksKey = {
  algorithm: SigningAlgorithm | string;
  curve: string;
  id: string;
  keyType: string;
};
