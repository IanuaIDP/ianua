import { proxyPipelineRequest, type PipelineRouteContext } from '../proxy';

export async function POST(request: Request, routeContext: PipelineRouteContext) {
  return proxyPipelineRequest({
    actionPath: 'activate',
    method: 'POST',
    request,
    routeContext,
  });
}
