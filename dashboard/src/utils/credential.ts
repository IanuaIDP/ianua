import type { AttestationMethod } from '@/types/credential';

const VALID_ATTESTATION_METHODS: AttestationMethod[] = ['spiffe', 'aws', 'gcp', 'tpm'];

export function normalizeAttestationMethods(methods: string[]): AttestationMethod[] {
  return methods
    .map((method) => method.toLowerCase())
    .filter((method): method is AttestationMethod =>
      VALID_ATTESTATION_METHODS.includes(method as AttestationMethod),
    );
}

export function truncatePublicKey(publicKey: string, visibleChars = 24) {
  const singleLine = publicKey.replace(/\s+/g, '').replace(/-----[A-Z ]+-----/g, '');

  if (singleLine.length <= visibleChars) {
    return singleLine;
  }

  return `${singleLine.slice(0, visibleChars)}...`;
}
