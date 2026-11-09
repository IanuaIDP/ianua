import { proxyAgentRunDetailRequest, type AgentRunDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: AgentRunDetailRouteContext) {
  return proxyAgentRunDetailRequest({ method: 'GET', request, routeContext });
}
