import { z } from 'zod';

export function parseDelimitedList(value?: string) {
  return (value ?? '')
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export type DecodedCapabilities = {
  http: string[];
  messaging: { rights: string; topic: string }[];
  resources: { relation: string; resource: string }[];
  tools: string[];
};

export function decodeCapabilities(values: string[]): DecodedCapabilities {
  const decoded: DecodedCapabilities = { http: [], messaging: [], resources: [], tools: [] };

  for (const value of values) {
    const [kind, ...rest] = value.split('|');

    if (kind === 'http' && rest[0]) {
      decoded.http.push(rest[0]);
    } else if (kind === 'msg' && rest[0] && rest[1]) {
      decoded.messaging.push({ rights: rest[1], topic: rest[0] });
    } else if (kind === 'res' && rest[0] && rest[1]) {
      decoded.resources.push({ relation: rest[0], resource: rest[1] });
    } else if (kind === 'tool' && rest[0]) {
      decoded.tools.push(rest[0]);
    }
  }

  return decoded;
}

export const GrantDelegationSchema = z
  .object({
    allowedPaths: z.string().optional(),
    apps: z.array(z.string()),
    capabilities: z.array(z.string()).min(1, 'validation.capabilityRequired'),
    maxDepth: z.string().min(1, 'validation.depthRequired'),
    name: z.string().optional(),
    purpose: z.string().optional(),
    purposeEnforcement: z.enum(['off', 'warn', 'enforce']),
    requestLimit: z.string().optional(),
    requestLimitWindowSeconds: z.string().min(1),
    requiresApproval: z.boolean().optional(),
    senderConstrained: z.boolean().optional(),
    task: z.string().optional(),
    thresholdBasisPoints: z.string().optional(),
    ttlSeconds: z.string().min(1, 'validation.expiryRequired'),
  })
  .superRefine((value, context) => {
    if (
      value.purpose?.trim() &&
      value.purposeEnforcement !== 'off' &&
      !value.thresholdBasisPoints?.trim()
    ) {
      context.addIssue({
        code: 'custom',
        message: 'validation.driftRequired',
        path: ['thresholdBasisPoints'],
      });
    }

    if (value.thresholdBasisPoints?.trim()) {
      const parsed = Number(value.thresholdBasisPoints);

      if (!Number.isInteger(parsed) || parsed < 0 || parsed > 10000) {
        context.addIssue({
          code: 'custom',
          message: 'validation.driftRange',
          path: ['thresholdBasisPoints'],
        });
      }
    }

    if (value.requestLimit?.trim()) {
      const parsed = Number(value.requestLimit);

      if (!Number.isInteger(parsed) || parsed <= 0) {
        context.addIssue({
          code: 'custom',
          message: 'validation.positiveInteger',
          path: ['requestLimit'],
        });
      }
    }

    if (value.task?.trim() && value.task.trim().length > 500) {
      context.addIssue({
        code: 'custom',
        message: 'validation.taskTooLong',
        path: ['task'],
      });
    }
  });

export type GrantDelegationInput = z.infer<typeof GrantDelegationSchema>;

export const GrantResourceAccessSchema = z.object({
  relation: z.string().min(1, 'validation.relationRequired'),
  resource: z.string().min(1, 'validation.resourceRequired'),
});

export type GrantResourceAccessInput = z.infer<typeof GrantResourceAccessSchema>;

export const CheckAuthorizationSchema = z
  .object({
    action: z.string().optional(),
    checkMode: z.enum(['capability', 'request']),
    method: z.string().optional(),
    path: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.checkMode === 'capability') {
      if (!value.action?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'validation.capabilityPick',
          path: ['action'],
        });
      }

      return;
    }

    if (!value.method?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.methodPick',
        path: ['method'],
      });
    }

    if (!value.path?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.requestPathRequired',
        path: ['path'],
      });
    }
  });

export type CheckAuthorizationInput = z.infer<typeof CheckAuthorizationSchema>;
