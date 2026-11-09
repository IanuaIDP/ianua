import { proxyAgentCredentialDetailRequest, type AgentCredentialDetailRouteContext } from './proxy';

export async function DELETE(request: Request, routeContext: AgentCredentialDetailRouteContext) {
  return proxyAgentCredentialDetailRequest({ method: 'DELETE', request, routeContext });
}
