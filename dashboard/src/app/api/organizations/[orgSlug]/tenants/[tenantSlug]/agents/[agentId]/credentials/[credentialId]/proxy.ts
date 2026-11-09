import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type AgentCredentialDetailRouteContext = {
  params: Promise<{
    agentId: string;
    credentialId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyAgentCredentialDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'POST';
  request: Request;
  routeContext: AgentCredentialDetailRouteContext;
};

export async function proxyAgentCredentialDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyAgentCredentialDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { agentId, credentialId, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'agents',
    encodeURIComponent(agentId),
    'credentials',
    encodeURIComponent(credentialId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody = method === 'DELETE' ? undefined : await readOptionalRequestBody(request);

  const response = await fetch(backendUrl, {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method,
  });

  return createProxyResponse(response);
}
