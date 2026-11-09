import { z } from 'zod';

const FIELD_PATH_SEGMENT = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const MAX_FIELD_PATH_LENGTH = 256;
const MAX_FIELD_PATH_SEGMENTS = 10;

export const ClassificationRuleSchema = z.object({
  fieldPath: z
    .string()
    .min(1, 'validation.fieldPathRequired')
    .max(MAX_FIELD_PATH_LENGTH, 'validation.fieldPathTooLong')
    .refine((value) => !value.startsWith('.') && !value.endsWith('.'), 'validation.fieldPathDot')
    .refine(
      (value) => value.split('.').length <= MAX_FIELD_PATH_SEGMENTS,
      'validation.fieldPathTooDeep',
    )
    .refine(
      (value) => value.split('.').every((segment) => FIELD_PATH_SEGMENT.test(segment)),
      'validation.fieldPathFormat',
    ),
  level: z.enum(['Public', 'Internal', 'Confidential', 'Restricted']),
  redaction: z.enum(['Remove', 'Mask', 'Hash']),
});

export type ClassificationRuleInput = z.infer<typeof ClassificationRuleSchema>;
