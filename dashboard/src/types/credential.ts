export type CredentialAlgorithm = 'EdDSA' | 'ES256' | 'RS256';

export type CredentialStatus = 'Active' | 'Revoked' | 'Rotated';

export type AttestationMethod = 'aws' | 'gcp' | 'spiffe' | 'tpm';

export type CredentialAttestation = {
  method: AttestationMethod;
  subject: string;
};

export type Credential = {
  algorithm: CredentialAlgorithm;
  attestation: CredentialAttestation | null;
  createdAt: string;
  expiresAt: string | null;
  graceEndsAt: string | null;
  gracePeriodSeconds: number | null;
  id: string;
  kid: string;
  publicKey: string;
  rotatedAt: string | null;
  status: CredentialStatus;
};

export type CredentialAction = 'Revoke';

export type AttestationPolicy = {
  allowedOrigins: string[];
  methods: AttestationMethod[];
  reattestIntervalSeconds: number;
};
