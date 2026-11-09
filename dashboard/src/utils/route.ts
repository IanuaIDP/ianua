import type { PermissionValue } from '@/types/permission';
import type { RouteCustomPermission, RoutePolicy, RoutePolicyKind } from '@/types/route';

export function getRoutePolicyKind(policy: RoutePolicy): RoutePolicyKind {
  if (typeof policy === 'string') {
    return policy;
  }

  if ('RequireSystemPermission' in policy) {
    return 'RequireSystemPermission';
  }

  if ('RequireCustomPermission' in policy) {
    return 'RequireCustomPermission';
  }

  return 'RequireScope';
}

export function getRoutePolicySystemPermissions(policy: RoutePolicy): PermissionValue[] {
  if (typeof policy !== 'string' && 'RequireSystemPermission' in policy) {
    return policy.RequireSystemPermission;
  }

  return [];
}

export function getRoutePolicyCustomPermissions(policy: RoutePolicy): RouteCustomPermission[] {
  if (typeof policy !== 'string' && 'RequireCustomPermission' in policy) {
    return policy.RequireCustomPermission;
  }

  return [];
}

export function getRoutePolicyScopes(policy: RoutePolicy): string[] {
  if (typeof policy !== 'string' && 'RequireScope' in policy) {
    return policy.RequireScope;
  }

  return [];
}
