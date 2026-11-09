export type DeliveryMethod = 'Push' | 'Poll';

export type StreamStatus = 'Active' | 'Paused' | 'Disabled';

export type SecuritySignalType =
  | 'SessionRevoked'
  | 'SessionSuspended'
  | 'CredentialChanged'
  | 'AccountLocked'
  | 'AccountDisabled'
  | 'PermissionsChanged'
  | 'DeviceCompromised'
  | 'TokenCompromised'
  | 'RiskLevelChanged'
  | 'AssuranceChanged'
  | 'CredentialCompromised'
  | 'IdentifierChanged'
  | 'AccountPurged';

export type DeliveryStatus = 'Success' | 'Failed' | 'Timeout' | 'Unreachable' | 'Queued';

export type StreamAction = 'Edit' | 'Pause' | 'Resume' | 'Disable' | 'Delete';

export type Stream = {
  consecutiveFailures: number;
  created: string;
  deliveryMethod: DeliveryMethod;
  endpoint: string;
  id: string;
  signalTypes: SecuritySignalType[];
  status: StreamStatus;
  updated: string;
  verification: string | null;
};

export type StreamList = {
  items: Stream[];
  limit: number;
  nextCursor: string | null;
};

export type StreamDelivery = {
  attemptNumber: number;
  attemptedAt: string;
  durationMs: number;
  id: string;
  responseStatus: number | null;
  signalId: string;
  signalType: SecuritySignalType;
  status: DeliveryStatus;
  streamId: string;
};

export type StreamDeliveryList = {
  items: StreamDelivery[];
  limit: number;
  nextCursor: string | null;
};
