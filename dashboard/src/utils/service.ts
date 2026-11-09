import type { GatewayService } from '@/types/gateway-service';

/// A discovered service's URL is only the fallback until the name resolves, so
/// the name is what describes where traffic actually goes.
export function formatServiceTarget(service: GatewayService): string {
  if (!service.discoveryName) {
    return service.upstreamUrl;
  }

  return `${service.discoveryName} (${service.discoveryKind.toUpperCase()})`;
}
