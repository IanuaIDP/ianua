import { proxyPipelineRequest, type PipelineRouteContext } from './proxy';

export async function GET(request: Request, routeContext: PipelineRouteContext) {
  return proxyPipelineRequest({ method: 'GET', request, routeContext });
}

export async function DELETE(request: Request, routeContext: PipelineRouteContext) {
  return proxyPipelineRequest({ method: 'DELETE', request, routeContext });
}
