export type DeviceState = 'trusted' | 'revoked';

export type DeviceStatus = 'Trusted' | 'Revoked';

export type TrustedDevice = {
  created: string;
  id: string;
  name: string;
  status: DeviceStatus;
};

export type DeviceAction = 'Revoke';
