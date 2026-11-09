import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    agentId: string;
    delegationId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export async function POST(request: Request, { params }: RouteContext) {
  return proxyDelegationResourcesRequest(request, { params }, 'POST');
}

export async function DELETE(request: Request, { params }: RouteContext) {
  return proxyDelegationResourcesRequest(request, { params }, 'DELETE');
}

async function proxyDelegationResourcesRequest(
  request: Request,
  { params }: RouteContext,
  method: 'DELETE' | 'POST',
) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { agentId, delegationId, orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendUrl = new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/agents/${encodeURIComponent(agentId)}/delegations/${encodeURIComponent(delegationId)}/resources`,
  );
  const requestBody = await readOptionalRequestBody(request);

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
