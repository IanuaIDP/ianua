const CONNECTION_TARGET_KEY = 'ianua-account-connection-target';

/** The tenant a service sign-in was begun in, kept only for this tab. */
export type AccountConnectionTarget = { orgSlug: string; tenantSlug: string };

export function saveAccountConnectionTarget(target: AccountConnectionTarget) {
  window.sessionStorage.setItem(CONNECTION_TARGET_KEY, JSON.stringify(target));
}

export function readAccountConnectionTarget(): AccountConnectionTarget | null {
  const stored = window.sessionStorage.getItem(CONNECTION_TARGET_KEY);

  if (!stored) {
    return null;
  }

  try {
    return JSON.parse(stored) as AccountConnectionTarget;
  } catch {
    return null;
  }
}

export function clearAccountConnectionTarget() {
  window.sessionStorage.removeItem(CONNECTION_TARGET_KEY);
}

export type ConnectionReturn =
  | { connectionId: string; code: string; kind: 'ready' }
  | { error: string; kind: 'failed' }
  | { kind: 'missing' };

/** Reads where the service sent the browser back to, from the part after `#`. */
export function readConnectionReturn(hash: string): ConnectionReturn {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const error = params.get('error');
  const connectionId = params.get('connection');
  const code = params.get('code');

  if (error) {
    return { error, kind: 'failed' };
  }

  return connectionId && code ? { code, connectionId, kind: 'ready' } : { kind: 'missing' };
}
