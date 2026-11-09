import { proxyRoleDetailRequest } from '../../proxy';

type AssignmentDetailRouteContext = {
  params: Promise<{
    orgSlug: string;
    roleId: string;
    tenantSlug: string;
    userId: string;
  }>;
};

export async function DELETE(request: Request, routeContext: AssignmentDetailRouteContext) {
  const { orgSlug, roleId, tenantSlug, userId } = await routeContext.params;

  return proxyRoleDetailRequest({
    actionPath: `assignments/${encodeURIComponent(userId)}`,
    method: 'DELETE',
    request,
    routeContext: {
      params: Promise.resolve({ orgSlug, roleId, tenantSlug }),
    },
  });
}
