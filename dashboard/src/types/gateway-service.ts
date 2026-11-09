import type { StickySession, WeightedBackend } from '@/types/route';

/// How a service's backends are found when they are not written down.
///
/// `srv` records carry a port and a weight per target, which is what a service
/// registry publishes. `address` records carry neither, so the port comes from
/// the service's own URL and every target is weighted the same.
export type DiscoveryKind = 'address' | 'srv';

export type GatewayServiceStatus = 'Active' | 'Disabled';

export type GatewayServiceSortField = 'created_at' | 'updated_at' | 'name';

export type GatewayServiceSortDirection = 'asc' | 'desc';

/// What happens to a signed-out browser on a page that needs sign-in.
export type SignedOutBrowsers = 'refuse' | 'redirect';

/// One path per sign-in address an app's host answers.
export type SignInAddresses = {
  login: string;
  logout: string;
  mfa: string;
  signup: string;
  verify: string;
};

/// How another service's sign-in reaches a service accepting it.
export type SignInDeliveryKind = 'same_host' | 'own_cookie' | 'tokens';

export type SignInDelivery =
  { kind: 'same_host' } | { hosts: string[]; kind: 'own_cookie' } | { kind: 'tokens' };

/// The sign-in addresses the gateway answers on a service's hosts.
export type AppSignIn = {
  /// Every address, where it answers now.
  addresses: SignInAddresses;
  afterSignIn: string;
  hosts: string[];
  /// The addresses moved off the prefix; the rest are absent.
  paths: Partial<SignInAddresses>;
  prefix: string;
  signedOutBrowsers: SignedOutBrowsers;
};

/// A backend the tenant's routes forward to.
///
/// Named "gateway service" here to keep it distinct from the `lib/api/services`
/// directory, which is this app's own naming for API client modules.
/// How often a service's backends are probed and how many answers decide.
export type HealthCheckTimings = {
  healthyThreshold: number;
  intervalSecs: number;
  panicThresholdPercent: number;
  timeoutSecs: number;
  unhealthyThreshold: number;
};

export type UpstreamTls = {
  caCertificates: string | null;
  clientCertificate: string | null;
  serverName: string | null;
};

export type GatewayService = {
  /** TLS the proxy uses towards this service; `null` means the platform default. */
  upstreamTls: UpstreamTls | null;
  /// The service whose app sign-in this one accepts instead, if any.
  acceptsAppSignInOf: string | null;
  /// How that sign-in reaches this service; `null` when it accepts none.
  signInDelivery: SignInDelivery | null;
  additionalBackends: WeightedBackend[];
  /// Sign-in on the hosts this service is served on; `null` for none.
  appSignIn: AppSignIn | null;
  discoveryKind: DiscoveryKind;
  /// The name whose targets the proxy resolves, empty when the backends above
  /// are the whole list.
  discoveryName: string;
  discoveryRefreshSecs: number;
  expectedAudience: string;
  /// False when probing is off — every backend stays eligible.
  healthCheckEnabled: boolean;
  healthCheckPath: string;
  /// The probe timings the API holds, sent back unchanged on save so editing
  /// the path doesn't reset them; `null` when probing is off.
  healthCheckTimings: HealthCheckTimings | null;
  id: string;
  name: string;
  preserveHost: boolean;
  requireClientCertificate: boolean;
  status: GatewayServiceStatus;
  stickySession: StickySession | null;
  timeoutSecs: number;
  upstreamUrl: string;
};

export type GatewayServiceAction = 'Edit' | 'Delete';

export type GatewayServiceList = {
  items: GatewayService[];
  limit: number;
  nextCursor: string | null;
};
