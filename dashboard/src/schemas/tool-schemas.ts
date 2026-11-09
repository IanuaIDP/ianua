import { z } from 'zod';

function isValidJsonSchemaObject(value: string) {
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

export const RegisterToolSchema = z.object({
  description: z.string().min(1, 'validation.descriptionRequired'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  name: z.string().min(1, 'validation.toolNameRequired').max(100, 'validation.toolNameTooLong'),
  path: z
    .string()
    .min(1, 'validation.pathPatternRequired')
    .refine((value) => value.startsWith('/'), { message: 'validation.pathSlash' }),
  routeId: z.string().min(1, 'validation.toolRouteRequired'),
  schema: z
    .string()
    .min(1, 'validation.schemaRequired')
    .refine(isValidJsonSchemaObject, { message: 'validation.schemaInvalid' }),
});

export type RegisterToolInput = z.infer<typeof RegisterToolSchema>;
