import type { WorkflowMappedField, WorkflowSource } from '@/types/workflow-graph';

const FIELD_PATTERN = /^[A-Za-z0-9_-]+$/;
const PATH_PATTERN = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;

export function isValidFieldName(value: string) {
  return FIELD_PATTERN.test(value);
}

export function isValidPath(value: string) {
  return PATH_PATTERN.test(value);
}

export function isSourceFilled(source: WorkflowSource | undefined) {
  if (!source) {
    return false;
  }

  if (source.from === 'input') {
    return isValidPath(source.path);
  }

  const { value } = source;

  if (value === null || value === undefined || value === '') {
    return false;
  }

  if (Array.isArray(value)) {
    return value.length > 0;
  }

  return typeof value !== 'object' || Object.keys(value).length > 0;
}

export function getMappedSource(fields: WorkflowMappedField[], field: string) {
  return fields.find((mapped) => mapped.field === field);
}

/** The mapping with `field` set to `source`, or without it when `source` is empty. */
export function setMappedSource(
  fields: WorkflowMappedField[],
  field: string,
  source: WorkflowSource | undefined,
): WorkflowMappedField[] {
  const others = fields.filter((mapped) => mapped.field !== field);

  return isSourceFilled(source) && source
    ? [...others, { ...source, field } as WorkflowMappedField]
    : others;
}
