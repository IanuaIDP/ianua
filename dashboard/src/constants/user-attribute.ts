import type { UserAttributeInput } from '@/schemas/user-attribute-schemas';
import type { UserAttributeKind, UserAttributeOperator } from '@/types/user-attribute';

/**
 * An example of what each kind holds, to make the choice concrete.
 *
 * Each one is written exactly as a stored value of that kind reads back in
 * the user list, so the tile is a promise the table keeps.
 */
export const ATTRIBUTE_KIND_EXAMPLES: Record<UserAttributeKind, string> = {
  colour: '#b1f15e',
  country: 'Netherlands',
  date: 'Sep 17, 2026',
  date_time: 'Sep 17, 2026, 09:30',
  decimal: '1.5',
  email: 'name@example.com',
  link: 'https://example.com',
  long_text: 'A few lines of notes',
  money: '45,000.00',
  multiple_choice: 'Rust, SQL',
  percent: '20%',
  phone: '+31 6 12345678',
  rating: '4 of 5 stars',
  single_choice: 'Sales',
  tags: 'urgent, reviewed',
  text: 'Engineering',
  whole_number: '42,000',
  yes_no: 'Yes',
};

/** How each comparison reads in a filter bar. */
export const OPERATOR_LABELS: Record<UserAttributeOperator, string> = {
  contains: 'contains',
  greater_than: 'is greater than',
  greater_than_or_equal: 'is at least',
  has_all: 'has all of',
  has_any: 'has any of',
  is: 'is',
  is_absent: 'is empty',
  is_not: 'is not',
  is_one_of: 'is one of',
  is_present: 'is set',
  less_than: 'is less than',
  less_than_or_equal: 'is at most',
};

/** The comparisons that take no value of their own. */
export const VALUELESS_OPERATORS: UserAttributeOperator[] = ['is_absent', 'is_present'];

/** The comparisons that take a comma-separated list. */
export const MULTI_VALUE_OPERATORS: UserAttributeOperator[] = ['has_all', 'has_any', 'is_one_of'];

/** The id that ties the add/edit field dialog's submit button to its form. */
export const USER_ATTRIBUTE_FORM_ID = 'user-attribute-form';

/** The id that ties the Edit user fields dialog's submit button to its form. */
export const EDIT_USER_FIELDS_FORM_ID = 'edit-user-fields-form';

/** The kind a new field starts as — the most common one. */
export const DEFAULT_ATTRIBUTE_KIND: UserAttributeKind = 'text';

/** A new field's starting values. */
export const EMPTY_ATTRIBUTE_FORM_VALUES: UserAttributeInput = {
  control: '',
  description: '',
  displayName: '',
  filterable: false,
  key: '',
  kind: DEFAULT_ATTRIBUTE_KIND,
  listed: true,
  maxLength: '',
  maximum: '',
  minimum: '',
  namespace: 'app',
  options: [],
  required: false,
  sensitive: false,
  sortable: false,
};

/** Who maintains a field's value; the names are in the messages. */
export const ATTRIBUTE_NAMESPACES = ['app', 'user'] as const;
