import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type AgentApprovalDetailRouteContext = {
  params: Promise<{
    agentId: string;
    approvalId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

type ProxyAgentApprovalDetailRequestOptions = {
  actionPath?: string;
  method: 'GET' | 'POST';
  request: Request;
  routeContext: AgentApprovalDetailRouteContext;
};

export async function proxyAgentApprovalDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyAgentApprovalDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { agentId, approvalId, orgSlug, tenantSlug } = await routeContext.params;
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
    'approvals',
    encodeURIComponent(approvalId),
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
