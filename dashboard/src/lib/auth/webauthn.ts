type PasskeyChallengePayload = {
  publicKey: unknown;
};

function base64UrlToBase64(value: string) {
  const padding = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));

  return value.replace(/-/g, '+').replace(/_/g, '/') + padding;
}

export function decodeBase64Url(value: string): Uint8Array {
  const binary = atob(base64UrlToBase64(value));

  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodePasskeyChallenge(challenge: string): PasskeyChallengePayload {
  const decoded = new TextDecoder().decode(decodeBase64Url(challenge));

  return JSON.parse(decoded) as PasskeyChallengePayload;
}

export function encodePasskeyCredentialResponse(credential: PublicKeyCredential): string {
  const json = JSON.stringify(credential.toJSON());

  return encodeBase64Url(new TextEncoder().encode(json));
}

/**
 * Feature-detects WebAuthn availability. Deliberately does NOT gate on
 * `isUserVerifyingPlatformAuthenticatorAvailable()` — that only reports platform
 * authenticators (Touch ID, Windows Hello) and would hide passkey UI entirely for
 * anyone whose only authenticator is a security key, even though `credentials.create`
 * / `credentials.get` work fine for cross-platform authenticators too.
 */
export async function isPasskeySupported(): Promise<boolean> {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
}

export async function isPasskeyConditionalMediationAvailable(): Promise<boolean> {
  if (
    typeof window === 'undefined' ||
    !window.PublicKeyCredential?.isConditionalMediationAvailable
  ) {
    return false;
  }

  try {
    return await PublicKeyCredential.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

export async function createPasskeyCredential(challenge: string): Promise<PublicKeyCredential> {
  const { publicKey } = decodePasskeyChallenge(challenge);
  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(
      publicKey as PublicKeyCredentialCreationOptionsJSON,
    ),
  });

  if (!credential) {
    throw new Error('Passkey registration was cancelled.');
  }

  return credential as PublicKeyCredential;
}

type GetPasskeyCredentialOptions = {
  mediation?: CredentialMediationRequirement;
  signal?: AbortSignal;
};

export async function getPasskeyCredential(
  challenge: string,
  options?: GetPasskeyCredentialOptions,
): Promise<PublicKeyCredential | null> {
  const { publicKey } = decodePasskeyChallenge(challenge);
  const credential = await navigator.credentials.get({
    mediation: options?.mediation,
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(
      publicKey as PublicKeyCredentialRequestOptionsJSON,
    ),
    signal: options?.signal,
  });

  return credential as PublicKeyCredential | null;
}

export type WebAuthnErrorKind = 'aborted' | 'cancelled' | 'security' | 'unknown';

/**
 * Classifies browser-side WebAuthn rejections so callers can decide the UX:
 * - `cancelled` (`NotAllowedError`): user dismissed the prompt or it timed out — return
 *   to the form silently, no error toast.
 * - `aborted` (`AbortError`): we cancelled the pending `get()` ourselves (e.g. the user
 *   submitted the password form while a conditional-UI prompt was pending) — no-op.
 * - `security` (`SecurityError`): origin doesn't match the server's configured relying
 *   party — a config problem, not a user error.
 */
export function classifyWebAuthnError(error: unknown): WebAuthnErrorKind {
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError') {
      return 'cancelled';
    }

    if (error.name === 'AbortError') {
      return 'aborted';
    }

    if (error.name === 'SecurityError') {
      return 'security';
    }
  }

  return 'unknown';
}
