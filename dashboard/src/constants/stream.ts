import type { DeliveryMethod, StreamStatus } from '@/types/stream';

export const STREAM_DELIVERY_METHODS: DeliveryMethod[] = ['Push', 'Poll'];

export const ALL_SIGNAL_TYPES_VALUE = '__all__';

/** Ids of the signal types; the visible names are `dashboard.streams.signalTypes.<id>`. */
export const STREAM_REAL_SIGNAL_TYPE_IDS = [
  'SessionRevoked',
  'SessionSuspended',
  'CredentialChanged',
  'AccountLocked',
  'AccountDisabled',
  'PermissionsChanged',
  'DeviceCompromised',
  'TokenCompromised',
  'RiskLevelChanged',
  'AssuranceChanged',
  'CredentialCompromised',
  'IdentifierChanged',
  'AccountPurged',
];

export const STREAM_REAL_SIGNAL_TYPE_VALUES: string[] = STREAM_REAL_SIGNAL_TYPE_IDS;

/**
 * Reconciles a multiselect's raw next-value array with the "All signal
 * types" pseudo-option so the two stay in sync in both directions:
 * checking "All" selects every real type, and selecting every real type
 * individually auto-checks "All". The pseudo-option is stripped out again
 * in the API payload: the backend needs every type named and refuses an
 * empty list.
 */
export function resolveStreamSignalTypesSelection(
  previousValues: string[],
  nextValues: string[],
): string[] {
  const allWasSelected = previousValues.includes(ALL_SIGNAL_TYPES_VALUE);
  const allIsSelected = nextValues.includes(ALL_SIGNAL_TYPES_VALUE);

  if (allIsSelected !== allWasSelected) {
    return allIsSelected ? [ALL_SIGNAL_TYPES_VALUE, ...STREAM_REAL_SIGNAL_TYPE_VALUES] : [];
  }

  const selectedRealValues = nextValues.filter((value) => value !== ALL_SIGNAL_TYPES_VALUE);

  return selectedRealValues.length === STREAM_REAL_SIGNAL_TYPE_VALUES.length
    ? [ALL_SIGNAL_TYPES_VALUE, ...selectedRealValues]
    : selectedRealValues;
}

export const STREAM_STATUS_TABS: ('All' | StreamStatus)[] = ['All', 'Active', 'Paused', 'Disabled'];
