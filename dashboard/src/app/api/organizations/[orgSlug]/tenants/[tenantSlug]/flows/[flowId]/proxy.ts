import { NextResponse } from 'next/server';

import { createProxyResponse } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type FlowDetailRouteContext = {
  params: Promise<{
    flowId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyFlowDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'POST';
  request: Request;
  routeContext: FlowDetailRouteContext;
};

export async function proxyFlowDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyFlowDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { flowId, orgSlug, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'flows',
    encodeURIComponent(flowId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);

  const response = await fetch(backendUrl, {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method,
  });

  return createProxyResponse(response);
}
