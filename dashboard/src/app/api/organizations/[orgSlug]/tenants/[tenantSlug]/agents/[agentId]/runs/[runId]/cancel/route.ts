import { proxyAgentRunDetailRequest, type AgentRunDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: AgentRunDetailRouteContext) {
  return proxyAgentRunDetailRequest({
    actionPath: 'cancel',
    method: 'POST',
    request,
    routeContext,
  });
}
