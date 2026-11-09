import { apiClient } from '@/lib/api/client';

export type GatewayProbeRequest = {
  host: string;
  method: string;
  /// The tenant whose verified domains `host` must be one of.
  orgSlug: string;
  path: string;
  tenantSlug: string;
  token: string;
};

export type GatewayProbeResult = {
  body: string;
  correlationId: string | null;
  durationMs: number;
  reason: string | null;
  status: number;
  truncated: boolean;
};

/// Sends one request through the tenant's gateway and reports what came back.
///
/// Goes via this app's own server, not the browser: the gateway is a different
/// origin, so a request straight from the page never leaves it — and a request
/// that never leaves cannot show you the refusal you were trying to see.
export async function probeGateway(request: GatewayProbeRequest): Promise<GatewayProbeResult> {
  const response = await apiClient.post<GatewayProbeResult>('/gateway-probe', request, {
    baseURL: '/api',
  });

  return response.data;
}
