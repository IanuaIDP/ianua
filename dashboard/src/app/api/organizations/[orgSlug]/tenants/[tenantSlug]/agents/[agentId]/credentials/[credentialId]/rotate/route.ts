import {
  proxyAgentCredentialDetailRequest,
  type AgentCredentialDetailRouteContext,
} from '../proxy';

export async function POST(request: Request, routeContext: AgentCredentialDetailRouteContext) {
  return proxyAgentCredentialDetailRequest({
    actionPath: 'rotate',
    method: 'POST',
    request,
    routeContext,
  });
}
