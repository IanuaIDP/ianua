import { NextResponse } from 'next/server';

import { API_URL } from '@/constants/api';

type PassThroughContext = {
  params: Promise<{
    path: string[];
  }>;
};

const FORWARDED_REQUEST_HEADERS = [
  'accept',
  'authorization',
  'content-type',
  'cookie',
  'user-agent',
  'x-forwarded-for',
];
const FORWARDED_RESPONSE_HEADERS = [
  'cache-control',
  'content-type',
  'location',
  'referrer-policy',
  'set-cookie',
  'www-authenticate',
];

/**
 * ianua's public addresses on the dashboard's own address, passed to the API
 * as they are. A tenant's issuer is `<dashboard>/api/v1/organizations/…`, so
 * everything an app or identity provider is told to call lives here: OIDC
 * discovery, authorize, token and keys; SAML metadata and sign-on; the single
 * sign-on start, callback and answer. Redirects are not followed and cookies
 * travel both ways, since a sign-on is bound to the browser by one.
 */
async function forward(request: Request, routeContext: PassThroughContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { path } = await routeContext.params;
  const backendUrl = new URL([API_URL, ...path.map(encodeURIComponent)].join('/'));
  backendUrl.search = new URL(request.url).search;
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';

  const response = await fetch(backendUrl, {
    body: hasBody ? await request.arrayBuffer() : undefined,
    cache: 'no-store',
    headers: pickHeaders(request.headers, FORWARDED_REQUEST_HEADERS),
    method: request.method,
    redirect: 'manual',
  });

  return new Response(response.status === 204 ? null : await response.arrayBuffer(), {
    headers: pickHeaders(response.headers, FORWARDED_RESPONSE_HEADERS),
    status: response.status,
  });
}

function pickHeaders(source: Headers, names: string[]) {
  const picked = new Headers();

  names.forEach((name) => {
    const values = name === 'set-cookie' ? source.getSetCookie() : [source.get(name)];

    values.forEach((value) => {
      if (value) {
        picked.append(name, value);
      }
    });
  });

  return picked;
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
