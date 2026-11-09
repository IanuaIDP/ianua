import { z } from 'zod';

/// Lowercase ASCII with hyphens and underscores — the same shape the API
/// accepts, checked here so a typo is caught before a round trip.
const SEGMENT = /^[a-z0-9_-]+$/;

const segment = (field: 'action' | 'resource') =>
  z
    .string()
    .min(1, `validation.${field}KeyRequired`)
    .max(64, `validation.${field}KeyTooLong`)
    .regex(SEGMENT, `validation.${field}KeyFormat`);

const ActionSchema = z.object({
  displayName: z.string().min(1, 'validation.actionNameRequired'),
  implies: z.array(z.string()),
  key: segment('action'),
});

export const ResourceTypeSchema = z
  .object({
    actions: z.array(ActionSchema).min(1, 'validation.actionRequired'),
    dataClass: z.enum(['Public', 'Internal', 'Confidential', 'Restricted']),
    description: z.string(),
    displayName: z.string().min(1, 'validation.nameRequired'),
    key: segment('resource'),
  })
  .superRefine((values, ctx) => {
    // The prefix system permissions reserve. An application that could name a
    // resource `idp` could mint a permission indistinguishable from one the
    // platform itself enforces.
    if (values.key === 'idp' || values.key.startsWith('idp_') || values.key.startsWith('idp-')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.resourceKeyReserved',
        path: ['key'],
      });
    }

    const seen = new Set<string>();
    values.actions.forEach((action, index) => {
      if (seen.has(action.key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `validation.actionKeyDuplicate?key=${encodeURIComponent(action.key)}`,
          path: ['actions', index, 'key'],
        });
      }
      seen.add(action.key);
    });

    // A ladder that loops has no bottom: expanding any rung would confer every
    // other, which is never what the person who drew it meant.
    const impliedBy = new Map(values.actions.map((a) => [a.key, a.implies]));
    const settled = new Set<string>();

    function loops(from: string, path: Set<string>): boolean {
      if (path.has(from)) {
        return true;
      }
      if (settled.has(from)) {
        return false;
      }

      path.add(from);
      const reached = (impliedBy.get(from) ?? []).some((next) => loops(next, path));
      path.delete(from);
      settled.add(from);

      return reached;
    }

    values.actions.forEach((action, index) => {
      if (loops(action.key, new Set())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `validation.actionKeyLoop?key=${encodeURIComponent(action.key)}`,
          path: ['actions', index, 'implies'],
        });
      }
    });
  });

export type ResourceTypeInput = z.infer<typeof ResourceTypeSchema>;
