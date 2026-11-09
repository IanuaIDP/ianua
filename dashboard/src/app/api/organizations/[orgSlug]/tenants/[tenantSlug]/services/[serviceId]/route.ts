import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type ServiceDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    serviceId: string;
    tenantSlug: string;
  }>;
};

export async function GET(request: Request, routeContext: ServiceDetailRouteContext) {
  return proxyServiceDetailRequest(request, routeContext, 'GET');
}

export async function PATCH(request: Request, routeContext: ServiceDetailRouteContext) {
  return proxyServiceDetailRequest(request, routeContext, 'PATCH');
}

export async function DELETE(request: Request, routeContext: ServiceDetailRouteContext) {
  return proxyServiceDetailRequest(request, routeContext, 'DELETE');
}

async function proxyServiceDetailRequest(
  request: Request,
  routeContext: ServiceDetailRouteContext,
  method: 'DELETE' | 'GET' | 'PATCH',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, serviceId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/services/${encodeURIComponent(serviceId)}`,
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
