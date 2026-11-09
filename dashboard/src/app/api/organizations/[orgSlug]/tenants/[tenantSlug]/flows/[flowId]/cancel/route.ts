import { proxyFlowDetailRequest, type FlowDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: FlowDetailRouteContext) {
  return proxyFlowDetailRequest({ actionPath: 'cancel', method: 'POST', request, routeContext });
}
