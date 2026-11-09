import type { TenantAgentOwner, TenantAgentOwnerKind } from '@/types/tenant-agent';

export function shortId(id: string) {
  return id.slice(0, 8);
}

export function encodeOwnerValue(kind: TenantAgentOwnerKind, id: string) {
  return `${kind}:${id}`;
}

export function decodeOwnerValue(value: string): TenantAgentOwner | null {
  const separatorIndex = value.indexOf(':');

  if (separatorIndex === -1) {
    return null;
  }

  const kind = value.slice(0, separatorIndex);
  const id = value.slice(separatorIndex + 1);

  if (!id || (kind !== 'user' && kind !== 'org_user' && kind !== 'agent')) {
    return null;
  }

  return { id, kind };
}
