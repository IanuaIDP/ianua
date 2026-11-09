import { proxyAgentDetailRequest, type AgentDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({ method: 'GET', request, routeContext });
}

export async function PATCH(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({ method: 'PATCH', request, routeContext });
}

export async function DELETE(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({ method: 'DELETE', request, routeContext });
}
