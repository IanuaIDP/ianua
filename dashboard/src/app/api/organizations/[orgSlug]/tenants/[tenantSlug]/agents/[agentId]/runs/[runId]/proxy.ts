import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type AgentRunDetailRouteContext = {
  params: Promise<{
    agentId: string;
    orgSlug: string;
    runId: string;
    tenantSlug: string;
  }>;
};

type ProxyAgentRunDetailRequestOptions = {
  actionPath?: string;
  method: 'GET' | 'POST';
  request: Request;
  routeContext: AgentRunDetailRouteContext;
};

export async function proxyAgentRunDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyAgentRunDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { agentId, orgSlug, runId, tenantSlug } = await routeContext.params;
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
    'runs',
    encodeURIComponent(runId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody = method === 'GET' ? undefined : await readOptionalRequestBody(request);

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
