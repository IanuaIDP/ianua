import type { PermissionValue } from '@/types/permission';

export type RouteStatus = 'Active' | 'Disabled';

export type RouteAction =
  'Enable' | 'Disable' | 'Edit' | 'Delete' | 'OpenToWorkflows' | 'CloseToWorkflows';

export type RouteCustomPermission = {
  action: string;
  resource: string;
};

export type RoutePolicy =
  | 'Public'
  | 'Authenticated'
  | { RequireCustomPermission: RouteCustomPermission[] }
  | { RequireScope: string[] }
  | { RequireSystemPermission: PermissionValue[] };

export type RoutePolicyKind =
  | 'Authenticated'
  | 'Public'
  | 'RequireCustomPermission'
  | 'RequireScope'
  | 'RequireSystemPermission';

export type StickySession =
  | { kind: 'ConsumerId' }
  | { kind: 'Cookie'; value: string }
  | { kind: 'Header'; value: string }
  | { kind: 'SourceIp' }
  | { kind: 'UserId' };

export type StickySessionKind = StickySession['kind'];

export type WeightedBackend = {
  url: string;
  weight: number;
};

export type RouteSortField = 'priority' | 'created_at' | 'updated_at' | 'name' | 'status';

export type RouteSortDirection = 'asc' | 'desc';

/**
 * What the upstream sees instead of the path that arrived.
 *
 * `Template` builds the forwarded path from the parameters the route pattern
 * captured, so `/orders/{id}` can reach a backend expecting `/v2/order/{id}`.
 */
export type PathRewrite =
  { mode: 'keep' } | { mode: 'strip_prefix' } | { mode: 'template'; template: string };

export type PathRewriteMode = PathRewrite['mode'];

export type Route = {
  actionClass: string | null;
  attackModeUntil: string | null;
  conditions: unknown[];
  created: string;
  dataClass: string | null;
  /**
   * The tenant domains this route answers on. Empty means every one of them —
   * the API reads an absent restriction that way, because a route restricted
   * to nothing could never be requested at all.
   */
  hosts: string[];
  id: string;
  methods: string[];
  name: string;
  pathPattern: string;
  pathRewrite: PathRewrite;
  reach: string | null;
  workflowUse: string | null;
  /**
   * The pipeline this route runs. Every route names one — there is no tenant
   * default to fall back to, so a route never inherits a security posture
   * decided somewhere other than the route itself.
   */
  pipelineId: string;
  policy: RoutePolicy;
  priority: number;
  /**
   * The service this route forwards to. The address, timeout and backends live
   * on the service, so twenty routes to one backend share one definition of it
   * — and one view of whether it is healthy.
   */
  serviceId: string;
  status: RouteStatus;
};

export type RouteList = {
  items: Route[];
  limit: number;
  nextCursor: string | null;
};
