import type { RouteFormInput } from '@/schemas/route-schemas';
import type { ServiceFormInput } from '@/schemas/service-schemas';

/// The names given to the pipeline, service and route created by "Add example".
export const EXAMPLE_ROUTE_NAME = 'Example route';
export const EXAMPLE_PIPELINE_NAME = 'Example pipeline';
export const EXAMPLE_SERVICE_NAME = 'Example service';

/// Where the example route forwards to.
///
/// The platform's own health endpoint: always answering, harmless, and not a
/// third party that can be down on the day someone is being shown this.
export const EXAMPLE_UPSTREAM_URL = 'https://api.ianua.io/health';

/// The service the example route forwards to.
///
/// It pins an audience because the route below requires a permission, and a
/// route requiring authentication is refused unless its service says which
/// tokens the upstream accepts.
export function buildExampleService(upstreamUrl: string): ServiceFormInput {
  return {
    additionalBackends: [],
    discoveryEnabled: false,
    discoveryKind: 'address',
    discoveryName: '',
    discoveryRefreshSecs: '30',
    expectedAudience: upstreamUrl,
    healthCheckEnabled: false,
    healthCheckPath: '/healthz',
    healthCheckTimings: null,
    name: EXAMPLE_SERVICE_NAME,
    preserveHost: false,
    requireClientCertificate: false,
    stickySessionKind: 'None',
    stickySessionValue: '',
    timeoutSecs: '30',
    upstreamUrl,
  };
}

/// A route that exists so a freshly granted token has somewhere to go.
///
/// Granting access does not create anything to call, so the first request
/// anyone tries fails for a reason that has nothing to do with the grant. This
/// gives them a path that resolves, gated on a permission a delegation can
/// actually carry, pointing at an endpoint that is always up and returns
/// something harmless.
export function buildExampleRoute(pipelineId: string, serviceId: string): RouteFormInput {
  return {
    customPermissions: [],
    hostScope: 'All',
    hosts: [],
    methods: ['Get'],
    name: EXAMPLE_ROUTE_NAME,
    pathPattern: '/example',
    pathRewriteMode: 'strip_prefix',
    pathRewriteTemplate: '',
    pipelineId,
    // The permission the presets already grant, so a token minted from a
    // standard grant reaches this without anyone matching them up by hand.
    policyKind: 'RequireSystemPermission',
    priority: '100',
    scopes: [],
    serviceId,
    systemPermissions: [{ Routing: 'View' }],
  };
}
