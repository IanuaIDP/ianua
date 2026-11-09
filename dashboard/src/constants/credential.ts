import type { SelectOption } from '@/types/dashboard';
import type { AttestationMethod } from '@/types/credential';

export const CREDENTIAL_ALGORITHM_OPTIONS: SelectOption[] = [
  { label: 'EdDSA', value: 'EdDSA' },
  { label: 'ES256', value: 'ES256' },
  { label: 'RS256', value: 'RS256' },
];

/// Seconds offered for re-attestation; the wording is `dashboard.credentials.reattestIntervals.<seconds>`.
export const ATTESTATION_REATTEST_INTERVAL_SECONDS = ['900', '1800', '3600', '14400', '86400'];

/// Seconds offered for a credential's expiry ('' is the default); the wording is
/// `dashboard.credentials.expiry.<seconds>`, or `.default` for ''.
export const CREDENTIAL_EXPIRY_SECONDS = ['', '604800', '7776000'];

/// Values sent for each attestation method; the wording is `dashboard.credentials.methods.<method>`.
export const ATTESTATION_METHODS: AttestationMethod[] = ['spiffe', 'aws', 'gcp', 'tpm'];
