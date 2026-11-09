import { proxyAgentDetailRequest, type AgentDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: AgentDetailRouteContext) {
  return proxyAgentDetailRequest({
    actionPath: 'grant',
    method: 'POST',
    request,
    routeContext,
  });
}
