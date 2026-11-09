import type {
  DiscoveryKind,
  SignInAddresses,
  SignInDeliveryKind,
  SignedOutBrowsers,
} from '@/types/gateway-service';
import type { StickySessionKind } from '@/types/route';

/// The prefix sign-in addresses answer under unless moved.
export const DEFAULT_SIGN_IN_PREFIX = '/.ianua';

export const SIGN_IN_ADDRESS_KEYS: (keyof SignInAddresses)[] = [
  'login',
  'signup',
  'mfa',
  'verify',
  'logout',
];

/// Ids of the ways another service's sign-in reaches a service; the wording is
/// `dashboard.services.appSignIn.delivery.<id>` and `.deliveryHints.<id>`.
export const SIGN_IN_DELIVERY_KINDS: SignInDeliveryKind[] = ['same_host', 'own_cookie', 'tokens'];

/// What a signed-out browser gets on a page that needs sign-in.
export const SIGNED_OUT_BROWSER_KINDS: SignedOutBrowsers[] = ['refuse', 'redirect'];

/// Below this the proxy spends more time asking the resolver than serving.
export const MIN_DISCOVERY_REFRESH_SECS = 5;

/// An hour of not noticing that every replica moved is already a long outage.
export const MAX_DISCOVERY_REFRESH_SECS = 3600;

export const DEFAULT_DISCOVERY_REFRESH_SECS = 30;

export const DISCOVERY_KINDS: DiscoveryKind[] = ['srv', 'address'];

export const STICKY_SESSION_KINDS: ('None' | StickySessionKind)[] = [
  'None',
  'UserId',
  'ConsumerId',
  'Cookie',
  'Header',
  'SourceIp',
];
