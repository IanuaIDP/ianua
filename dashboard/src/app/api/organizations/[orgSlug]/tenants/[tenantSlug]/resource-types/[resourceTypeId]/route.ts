import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type ResourceTypeRouteContext = {
  params: Promise<{
    orgSlug: string;
    resourceTypeId: string;
    tenantSlug: string;
  }>;
};

export async function PATCH(request: Request, routeContext: ResourceTypeRouteContext) {
  return proxyResourceTypeRequest(request, routeContext, 'PATCH');
}

export async function DELETE(request: Request, routeContext: ResourceTypeRouteContext) {
  return proxyResourceTypeRequest(request, routeContext, 'DELETE');
}

async function proxyResourceTypeRequest(
  request: Request,
  routeContext: ResourceTypeRouteContext,
  method: 'DELETE' | 'PATCH',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, resourceTypeId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/resource-types/${encodeURIComponent(resourceTypeId)}`,
  );
  const requestBody = method === 'PATCH' ? await readOptionalRequestBody(request) : undefined;

  const response = await fetch(backendUrl, {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method,
  });

  return createProxyResponse(response);
}
