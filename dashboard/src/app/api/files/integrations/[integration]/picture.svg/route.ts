import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{ integration: string }>;
};

/**
 * An integration's picture. Answers bytes rather than JSON, and marks the file
 * so a browser opening it directly can never run anything inside it.
 */
export async function GET(_request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return new Response(null, { status: 500 });
  }

  const { integration } = await params;
  const response = await fetch(
    `${API_URL}/files/integrations/${encodeURIComponent(integration)}/picture.svg`,
    { cache: 'no-store' },
  );

  if (!response.ok) {
    return new Response(null, { status: response.status });
  }

  return new Response(await response.arrayBuffer(), {
    headers: {
      'Cache-Control': 'public, max-age=3600',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Content-Type': 'image/svg+xml',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
