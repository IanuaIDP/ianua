import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

export type StageDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    pipelineId: string;
    stageId: string;
    tenantSlug: string;
  }>;
};

type ProxyStageDetailRequestOptions = {
  actionPath?: string;
  method: 'DELETE' | 'POST';
  request: Request;
  routeContext: StageDetailRouteContext;
};

export async function proxyStageDetailRequest({
  actionPath,
  method,
  request,
  routeContext,
}: ProxyStageDetailRequestOptions) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { orgSlug, pipelineId, stageId, tenantSlug } = await routeContext.params;
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
    'stages',
    encodeURIComponent(stageId),
    actionPath,
  ]
    .filter(Boolean)
    .join('/');
  const backendUrl = new URL(backendPath);
  const requestBody = method !== 'DELETE' ? await readOptionalRequestBody(request) : undefined;

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
