import { z } from 'zod';

/** Lowercase letters, digits and single underscores — what the API accepts. */
const KEY = /^[a-z0-9]+(?:_[a-z0-9]+)*$/;

export const UserAttributeSchema = z
  .object({
    control: z.string(),
    description: z.string(),
    displayName: z
      .string()
      .min(1, 'validation.fieldNameRequired')
      .max(100, 'validation.fieldNameTooLong'),
    filterable: z.boolean(),
    key: z
      .string()
      .max(64, 'validation.keyTooLong')
      .refine((value) => value === '' || KEY.test(value), {
        message: 'validation.keyFormat',
      }),
    kind: z.string().min(1, 'validation.kindRequired'),
    listed: z.boolean(),
    maxLength: z.string(),
    maximum: z.string(),
    minimum: z.string(),
    namespace: z.enum(['app', 'user']),
    options: z.array(z.string()),
    required: z.boolean(),
    sensitive: z.boolean(),
    sortable: z.boolean(),
  })
  .superRefine((values, ctx) => {
    // The prefix the platform reserves for fields it may define itself.
    if (values.key.startsWith('idp_')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.keyReserved',
        path: ['key'],
      });
    }

    const filled = values.options.map((option) => option.trim()).filter(Boolean);

    if (requiresOptions(values.kind) && filled.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.optionRequired',
        path: ['options'],
      });
    }

    const seen = new Set<string>();
    values.options.forEach((option, index) => {
      const trimmed = option.trim();

      if (!trimmed) {
        return;
      }

      if (seen.has(trimmed)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'validation.optionDuplicate',
          path: ['options', index],
        });
      }

      seen.add(trimmed);
    });

    const minimum = toNumber(values.minimum);
    const maximum = toNumber(values.maximum);

    if (values.minimum && minimum === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.minimumNotNumber',
        path: ['minimum'],
      });
    }

    if (values.maximum && maximum === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.maximumNotNumber',
        path: ['maximum'],
      });
    }

    if (minimum !== undefined && maximum !== undefined && minimum > maximum) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.rangeInverted',
        path: ['minimum'],
      });
    }

    const maxLength = toNumber(values.maxLength);

    if (values.maxLength && (maxLength === undefined || maxLength < 1)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.maxLengthInvalid',
        path: ['maxLength'],
      });
    }
  });

export type UserAttributeInput = z.infer<typeof UserAttributeSchema>;

/** The kinds whose values are chosen from a declared list. */
export function requiresOptions(kind: string) {
  return kind === 'single_choice' || kind === 'multiple_choice';
}

/** Reads a number a person typed, or `undefined` when they typed nothing usable. */
export function toNumber(value: string) {
  const trimmed = value.trim();

  if (!trimmed) {
    return undefined;
  }

  const parsed = Number(trimmed);

  return Number.isFinite(parsed) ? parsed : undefined;
}
