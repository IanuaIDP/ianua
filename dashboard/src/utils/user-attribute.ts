import type { UserAttributeInput } from '@/schemas/user-attribute-schemas';
import type { UserAttribute, UserAttributeValue } from '@/types/user-attribute';

/** How a field is addressed everywhere, including in a user's stored values. */
export function getAttributeId(attribute: Pick<UserAttribute, 'key' | 'namespace'>) {
  return `${attribute.namespace}.${attribute.key}`;
}

/** `Annual income` → `annual_income`, matching what the API derives. */
export function deriveAttributeKey(displayName: string) {
  return displayName
    .split('')
    .map((character) => (/[a-zA-Z0-9]/.test(character) ? character.toLowerCase() : ' '))
    .join('')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .join('_');
}

/** A declared field as the add/edit field form edits it. */
export function toAttributeFormValues(attribute: UserAttribute): UserAttributeInput {
  return {
    control: attribute.control,
    description: attribute.description ?? '',
    displayName: attribute.displayName,
    filterable: attribute.filterable,
    key: attribute.key,
    kind: attribute.kind,
    listed: attribute.listed,
    maxLength: attribute.maxLength === undefined ? '' : String(attribute.maxLength),
    maximum: attribute.maximum === undefined ? '' : String(attribute.maximum),
    minimum: attribute.minimum === undefined ? '' : String(attribute.minimum),
    namespace: attribute.namespace,
    options: attribute.options,
    required: attribute.required,
    sensitive: attribute.sensitive,
    sortable: attribute.sortable,
  };
}

/** An empty value of any shape reads as "not set", which is what clears it. */
export function isBlankAttributeValue(value: UserAttributeValue) {
  if (Array.isArray(value)) {
    return value.length === 0;
  }

  return value === null || value === undefined || value === '';
}

export function isSameAttributeValue(left: UserAttributeValue, right: UserAttributeValue) {
  if (isBlankAttributeValue(left) && isBlankAttributeValue(right)) {
    return true;
  }

  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((entry, index) => entry === right[index]);
  }

  return left === right;
}
