import { z } from 'zod';

function isNonNegativeInteger(value: string) {
  return /^\d+$/.test(value.trim());
}

const RouteCustomPermissionFormSchema = z.object({
  action: z.string(),
  resource: z.string(),
});

export const RouteFormSchema = z
  .object({
    customPermissions: z.array(RouteCustomPermissionFormSchema),
    hostScope: z.enum(['All', 'Specific']),
    hosts: z.array(z.string()),
    methods: z.array(z.string()).min(1, 'validation.methodRequired'),
    name: z.string().min(1, 'validation.nameRequired'),
    pathPattern: z.string().min(1, 'validation.pathPatternRequired'),
    pathRewriteMode: z.enum(['keep', 'strip_prefix', 'template']),
    pathRewriteTemplate: z.string(),
    pipelineId: z.string().min(1, 'validation.pipelineRequired'),
    policyKind: z.enum([
      'Public',
      'Authenticated',
      'RequireSystemPermission',
      'RequireCustomPermission',
      'RequireScope',
    ]),
    priority: z.string().refine(isNonNegativeInteger, 'validation.priorityInvalid'),
    scopes: z.array(z.string()),
    serviceId: z.string().min(1, 'validation.serviceRequired'),
    systemPermissions: z.array(z.record(z.string(), z.string())),
  })
  .superRefine((values, ctx) => {
    if (values.hostScope === 'Specific' && values.hosts.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.hostsRequired',
        path: ['hosts'],
      });
    }

    if (values.pathRewriteMode === 'template' && !values.pathRewriteTemplate.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.rewriteTemplateRequired',
        path: ['pathRewriteTemplate'],
      });
    }

    if (values.policyKind === 'RequireSystemPermission' && values.systemPermissions.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.systemPermissionRequired',
        path: ['systemPermissions'],
      });
    }

    if (values.policyKind === 'RequireCustomPermission') {
      if (values.customPermissions.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'validation.customPermissionRequired',
          path: ['customPermissions'],
        });
      }

      values.customPermissions.forEach((permission, index) => {
        if (!permission.resource.trim()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'validation.resourceRequired',
            path: ['customPermissions', index, 'resource'],
          });
        }

        if (!permission.action.trim()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'validation.permissionActionRequired',
            path: ['customPermissions', index, 'action'],
          });
        }
      });
    }

    if (values.policyKind === 'RequireScope' && values.scopes.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.scopeRequired',
        path: ['scopes'],
      });
    }
  });

export type RouteFormInput = z.infer<typeof RouteFormSchema>;
