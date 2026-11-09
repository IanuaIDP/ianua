import { NextResponse } from 'next/server';

import { createProxyResponse, readOptionalRequestBody } from '@/app/api/_utils/proxy';
import { API_URL } from '@/constants/api';

type RouteContext = {
  params: Promise<{
    domainId: string;
    orgSlug: string;
    tenantSlug: string;
  }>;
};

function getBackendUrl(orgSlug: string, tenantSlug: string, domainId: string) {
  return new URL(
    `${API_URL}/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/domains/${encodeURIComponent(domainId)}/dns`,
  );
}

export async function GET(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { domainId, orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');

  const response = await fetch(getBackendUrl(orgSlug, tenantSlug, domainId), {
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
    },
    method: 'GET',
  });

  return createProxyResponse(response);
}

export async function PUT(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { domainId, orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestBody = await readOptionalRequestBody(request);

  const response = await fetch(getBackendUrl(orgSlug, tenantSlug, domainId), {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method: 'PUT',
  });

  return createProxyResponse(response);
}

export async function DELETE(request: Request, { params }: RouteContext) {
  if (!API_URL) {
    return NextResponse.json(
      { error: 'CONFIG_ERROR', message: 'API_URL is not configured.' },
      { status: 500 },
    );
  }

  const { domainId, orgSlug, tenantSlug } = await params;
  const authorization = request.headers.get('authorization');
  const contentType = request.headers.get('content-type');
  const requestBody = await readOptionalRequestBody(request);

  const response = await fetch(getBackendUrl(orgSlug, tenantSlug, domainId), {
    body: requestBody,
    cache: 'no-store',
    headers: {
      ...(authorization ? { Authorization: authorization } : {}),
      ...(requestBody && contentType ? { 'Content-Type': contentType } : {}),
    },
    method: 'DELETE',
  });

  return createProxyResponse(response);
}
