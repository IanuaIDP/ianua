import { NextResponse } from 'next/server';

export async function createProxyResponse(response: Response) {
  const responseText = await response.text();

  if (response.status === 204 || response.status === 205) {
    return new Response(null, { status: response.status });
  }

  if (!responseText) {
    return NextResponse.json(null, { status: response.status });
  }

  const parsed = tryParseJson(responseText);

  if (parsed === null && isHtmlBody(responseText)) {
    return NextResponse.json({}, { status: response.status });
  }

  return NextResponse.json(parsed ?? { message: responseText }, {
    status: response.status,
  });
}

/// An ingress's error page is markup, not a message a person should read.
function isHtmlBody(value: string) {
  return /^\s*<(!doctype|html)/i.test(value);
}

/// Request headers that tell the backend who is really calling. Without them
/// every request reaches the API from this server's address, so rate limits,
/// lockouts and audit logs see one client instead of the real one.
///
/// `x-forwarded-for` is passed on as received: the ingress in front of this
/// app appends the connecting address, and the backend should trust only the
/// hops it knows about.
const CLIENT_HEADERS = ['user-agent', 'x-forwarded-for', 'x-real-ip'] as const;

export function getForwardedClientHeaders(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};

  CLIENT_HEADERS.forEach((name) => {
    const value = request.headers.get(name);

    if (value) {
      headers[name] = value;
    }
  });

  return headers;
}

export async function readOptionalRequestBody(request: Request) {
  const contentLength = request.headers.get('content-length');
  const transferEncoding = request.headers.get('transfer-encoding');

  if ((!contentLength || contentLength === '0') && !transferEncoding) {
    return undefined;
  }

  const requestBody = await request.text();

  return requestBody || undefined;
}

function tryParseJson(value: string) {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}
