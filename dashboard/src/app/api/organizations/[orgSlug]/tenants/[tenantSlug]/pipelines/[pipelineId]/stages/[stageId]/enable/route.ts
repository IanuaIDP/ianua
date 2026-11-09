import { proxyStageDetailRequest, type StageDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: StageDetailRouteContext) {
  return proxyStageDetailRequest({
    actionPath: 'enable',
    method: 'POST',
    request,
    routeContext,
  });
}
