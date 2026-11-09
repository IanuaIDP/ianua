import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { NextResponse } from 'next/server';

import { API_URL } from '@/constants/api';

/// Sends one request through a tenant's gateway on the caller's behalf and
/// reports what came back.
///
/// It runs here rather than in the browser because the gateway is a different
/// origin: a request straight from the page is blocked before it is ever sent,
/// and the interesting answers — a 401 for a revoked grant, a 403 for a tool
/// outside it — are exactly the ones a blocked request never shows.
///
/// Because it makes requests from this server, it must not become an open
/// forwarder. A probe is only sent when:
/// - the caller has a dashboard session that can read the tenant's domains
///   (checked against the backend with the caller's own token),
/// - the host is one of that tenant's verified domains, and
/// - the host resolves to public addresses only.
///
/// The task token is forwarded, never logged, and never stored.
type ProbeRequest = {
  host?: unknown;
  method?: unknown;
  orgSlug?: unknown;
  path?: unknown;
  tenantSlug?: unknown;
  token?: unknown;
};

type DomainListResponse = {
  items?: { domain?: string | null; verification_status?: string | null }[];
};

/// How long to wait before calling it unreachable.
const TIMEOUT_MS = 10_000;

/// The largest response body read back into the preview.
const MAX_PREVIEW_BYTES = 2048;

/// Matches the list the dashboard offers in the Try access panel.
const DOMAIN_LOOKUP_LIMIT = 50;

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);

/// Pulls the proxy's explanation out of a denial body, when it is one.
function denialReason(body: string): string | null {
  try {
    const parsed: unknown = JSON.parse(body);
    const error = (parsed as { error?: unknown })?.error;
    return typeof error === 'string' ? error.replace(/^denied:\s*/, '') : null;
  } catch {
    return null;
  }
}

function errorResponse(status: number, error: string, message: string) {
  return NextResponse.json({ error, message }, { status });
}

function badRequest(message: string) {
  return errorResponse(400, 'INVALID_REQUEST', message);
}

/// True for loopback, private, link-local (including cloud metadata),
/// carrier-grade NAT, multicast and other non-public ranges.
function isNonPublicAddress(address: string): boolean {
  const version = isIP(address);

  if (version === 4) {
    const [a, b] = address.split('.').map(Number);

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }

  if (version === 6) {
    const normalized = address.toLowerCase();
    const mappedV4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);

    if (mappedV4) {
      return isNonPublicAddress(mappedV4[1]);
    }

    return (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb') ||
      normalized.startsWith('ff')
    );
  }

  return true;
}

/// Asks the backend, with the caller's own token, for the tenant's verified
/// domains. A failure here means the caller cannot see this tenant's domains,
/// so the probe is refused with the backend's status.
async function getVerifiedDomains(
  authorization: string,
  orgSlug: string,
  tenantSlug: string,
): Promise<{ domains: Set<string> } | { status: number }> {
  const url = new URL(
    [
      API_URL,
      'organizations',
      encodeURIComponent(orgSlug),
      'tenants',
      encodeURIComponent(tenantSlug),
      'domains',
    ].join('/'),
  );
  url.searchParams.set('limit', String(DOMAIN_LOOKUP_LIMIT));

  const response = await fetch(url, {
    cache: 'no-store',
    headers: { Authorization: authorization },
  });

  if (!response.ok) {
    return { status: response.status };
  }

  const list = (await response.json().catch(() => null)) as DomainListResponse | null;
  const domains = new Set(
    (list?.items ?? [])
      .filter((entry) => entry.verification_status?.toLowerCase() === 'verified')
      .map((entry) => entry.domain?.toLowerCase())
      .filter((domain): domain is string => Boolean(domain)),
  );

  return { domains };
}

export async function POST(request: Request) {
  if (!API_URL) {
    return errorResponse(500, 'CONFIG_ERROR', 'API_URL is not configured.');
  }

  const authorization = request.headers.get('authorization');

  if (!authorization) {
    return errorResponse(401, 'UNAUTHORIZED', 'Sign in to try a grant.');
  }

  const body = (await request.json().catch(() => null)) as ProbeRequest | null;

  if (!body) {
    return badRequest('Expected a JSON body.');
  }

  const { host, method, orgSlug, path, tenantSlug, token } = body;

  if (
    typeof host !== 'string' ||
    typeof path !== 'string' ||
    typeof token !== 'string' ||
    typeof orgSlug !== 'string' ||
    typeof tenantSlug !== 'string'
  ) {
    return badRequest('host, path, token, orgSlug and tenantSlug are required.');
  }

  const verb = typeof method === 'string' ? method.toUpperCase() : 'GET';

  if (!ALLOWED_METHODS.has(verb)) {
    return badRequest(`Unsupported method: ${verb}`);
  }

  // Built from a host and a path rather than a whole URL the caller supplies,
  // and always HTTPS on the default port.
  let target: URL;
  try {
    target = new URL(`https://${host.replace(/^https?:\/\//, '')}`);
    target.pathname = path.startsWith('/') ? path : `/${path}`;
  } catch {
    return badRequest('Could not build a URL from that host and path.');
  }

  if (target.protocol !== 'https:' || target.port || target.username || target.password) {
    return badRequest('The gateway must be a plain HTTPS host name.');
  }

  const hostname = target.hostname.toLowerCase();
  const verified = await getVerifiedDomains(authorization, orgSlug, tenantSlug);

  if ('status' in verified) {
    return errorResponse(
      verified.status === 401 ? 401 : 403,
      'FORBIDDEN',
      "You can't read this tenant's domains, so its gateway can't be tried from here.",
    );
  }

  if (!verified.domains.has(hostname)) {
    return errorResponse(403, 'FORBIDDEN', "Only the tenant's verified domains can be tried.");
  }

  // A verified domain still decides its own DNS. Refuse anything that points
  // back into this server's network.
  try {
    const addresses = await lookup(hostname, { all: true });

    if (!addresses.length || addresses.some((entry) => isNonPublicAddress(entry.address))) {
      return errorResponse(403, 'FORBIDDEN', 'That domain does not point to a public address.');
    }
  } catch {
    return errorResponse(502, 'UNREACHABLE', 'Could not resolve that domain.');
  }

  const startedAt = Date.now();

  try {
    const response = await fetch(target, {
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}` },
      method: verb,
      // A redirect could lead anywhere; report it instead of following it.
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    const text = await response.text();

    return NextResponse.json({
      body: text.slice(0, MAX_PREVIEW_BYTES),
      // Ties this attempt to the proxy's own audit record of it.
      correlationId: response.headers.get('x-correlation-id'),
      durationMs: Date.now() - startedAt,
      // A denial carries "denied: <why>" in its body, and the why is the whole
      // point of trying: "refused" is not an answer, "outside the token's
      // declared intent" is.
      reason: denialReason(text),
      status: response.status,
      truncated: text.length > MAX_PREVIEW_BYTES,
    });
  } catch (error) {
    const message =
      error instanceof Error && error.name === 'TimeoutError'
        ? 'The gateway did not answer in time.'
        : 'Could not reach the gateway at that address.';

    return errorResponse(502, 'UNREACHABLE', message);
  }
}
