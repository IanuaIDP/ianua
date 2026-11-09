import { proxyStageDetailRequest, type StageDetailRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: StageDetailRouteContext) {
  return proxyStageDetailRequest({
    actionPath: 'disable',
    method: 'POST',
    request,
    routeContext,
  });
}
