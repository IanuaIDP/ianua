export type PasskeyAuthenticatorType = 'platform' | 'cross_platform';

export type Passkey = {
  authenticatorType: PasskeyAuthenticatorType;
  created: string;
  id: string;
  lastUsed: string | null;
  name: string;
};

export type PasskeyCeremony = {
  ceremonyId: string;
  challenge: string;
};

export type PasskeyAction = 'Rename' | 'Remove';
