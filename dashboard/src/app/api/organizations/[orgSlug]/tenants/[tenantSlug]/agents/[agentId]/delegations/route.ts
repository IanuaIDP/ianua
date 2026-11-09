import { proxyAgentDetailRequest, type AgentDetailRouteContext } from '../proxy';

export async function GET(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({
    actionPath: 'delegations',
    method: 'GET',
    request,
    routeContext,
  });
}
