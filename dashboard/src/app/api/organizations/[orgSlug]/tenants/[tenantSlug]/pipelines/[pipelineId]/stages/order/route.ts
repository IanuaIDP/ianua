import { proxyPipelineRequest, type PipelineRouteContext } from '../../proxy';

export async function PUT(request: Request, routeContext: PipelineRouteContext) {
  return proxyPipelineRequest({
    actionPath: 'stages/order',
    method: 'PUT',
    request,
    routeContext,
  });
}
