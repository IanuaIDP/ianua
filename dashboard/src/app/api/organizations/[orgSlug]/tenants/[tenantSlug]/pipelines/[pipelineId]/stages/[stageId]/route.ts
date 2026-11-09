import { proxyStageDetailRequest, type StageDetailRouteContext } from './proxy';

export async function DELETE(request: Request, routeContext: StageDetailRouteContext) {
  return proxyStageDetailRequest({ method: 'DELETE', request, routeContext });
}
