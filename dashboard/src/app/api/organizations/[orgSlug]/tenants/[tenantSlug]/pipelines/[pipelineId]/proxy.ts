import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type PipelineRouteContext = {
  params: Promise<{
    orgSlug: string;
    pipelineId: string;
    tenantSlug: string;
  }>;
};

type ProxyPipelineRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'GET' | 'POST' | 'PUT';
  request: Request;
  routeContext: PipelineRouteContext;
};

export async function proxyPipelineRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyPipelineRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, pipelineId, tenantSlug } = await routeContext.params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const backendPath = [
    API_URL,
    'organizations',
    encodeURIComponent(orgSlug),
    'tenants',
    encodeURIComponent(tenantSlug),
    'pipelines',
    encodeURIComponent(pipelineId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody =
    method === 'DELETE' || method === 'GET' ? undefined : await readOptionalRequestBody(request);

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
