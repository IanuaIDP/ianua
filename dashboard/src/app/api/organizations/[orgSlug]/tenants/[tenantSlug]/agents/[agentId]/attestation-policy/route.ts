import { proxyAgentDetailRequest, type AgentDetailRouteContext } from '../proxy';

export async function PUT(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({
    actionPath: 'attestation-policy',
    method: 'PUT',
    request,
    routeContext,
  });
}
