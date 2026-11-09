import { proxyAgentApprovalDetailRequest, type AgentApprovalDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: AgentApprovalDetailRouteContext) {
  return proxyAgentApprovalDetailRequest({
    actionPath: 'deny',
    method: 'POST',
    request,
    routeContext,
  });
}
