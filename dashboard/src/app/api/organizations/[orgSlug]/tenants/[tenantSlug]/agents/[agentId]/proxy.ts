import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type AgentDetailRouteContext = {
  params: Promise<{
    agentId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyAgentDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  request: Request;
  routeContext: AgentDetailRouteContext;
};

export async function proxyAgentDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyAgentDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { agentId, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'agents',
    encodeURIComponent(agentId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  backendUrl.search = new URL(request.url).search;
  const hasBody = method !== 'GET' && method !== 'DELETE';
  const requestBody = hasBody ? await readOptionalRequestBody(request) : undefined;

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
