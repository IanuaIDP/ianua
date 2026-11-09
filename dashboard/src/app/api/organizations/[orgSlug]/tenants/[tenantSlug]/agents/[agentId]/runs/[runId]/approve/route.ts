import { proxyAgentRunDetailRequest, type AgentRunDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: AgentRunDetailRouteContext) {
  return proxyAgentRunDetailRequest({
    actionPath: 'approve',
    method: 'POST',
    request,
    routeContext,
  });
}
