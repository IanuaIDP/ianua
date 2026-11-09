import { proxyFlowDetailRequest, type FlowDetailRouteContext } from './proxy';

export async function GET(request: Request, routeContext: FlowDetailRouteContext) {
  return proxyFlowDetailRequest({ method: 'GET', request, routeContext });
}

export async function DELETE(request: Request, routeContext: FlowDetailRouteContext) {
  return proxyFlowDetailRequest({ method: 'DELETE', request, routeContext });
}
