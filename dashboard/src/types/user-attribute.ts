export type UserAttributeNamespace = 'app' | 'user';

/**
 * What kind of thing a field holds. The only choice an administrator makes —
 * the control, the valid values and the comparisons a filter may use all
 * follow from it.
 */
export type UserAttributeKind =
  | 'colour'
  | 'country'
  | 'date'
  | 'date_time'
  | 'decimal'
  | 'email'
  | 'link'
  | 'long_text'
  | 'money'
  | 'multiple_choice'
  | 'percent'
  | 'phone'
  | 'rating'
  | 'single_choice'
  | 'tags'
  | 'text'
  | 'whole_number'
  | 'yes_no';

/** The form control a client renders. A presentation hint; no query reads it. */
export type UserAttributeControl =
  | 'checkbox'
  | 'checkbox_group'
  | 'colour_picker'
  | 'country_select'
  | 'currency_input'
  | 'date_picker'
  | 'date_time_picker'
  | 'email_input'
  | 'multi_select'
  | 'number_input'
  | 'percent_input'
  | 'phone_input'
  | 'radio_group'
  | 'select'
  | 'slider'
  | 'star_rating'
  | 'tag_input'
  | 'text_area'
  | 'text_input'
  | 'toggle'
  | 'url_input';

export type UserAttributeOperator =
  | 'contains'
  | 'greater_than'
  | 'greater_than_or_equal'
  | 'has_all'
  | 'has_any'
  | 'is'
  | 'is_absent'
  | 'is_not'
  | 'is_one_of'
  | 'is_present'
  | 'less_than'
  | 'less_than_or_equal';

export type UserAttribute = {
  archived: boolean;
  availableControls: UserAttributeControl[];
  control: UserAttributeControl;
  createdAt: string;
  description?: string;
  displayName: string;
  filterable: boolean;
  key: string;
  kind: UserAttributeKind;
  listed: boolean;
  maxLength?: number;
  maximum?: number;
  minimum?: number;
  namespace: UserAttributeNamespace;
  operators: UserAttributeOperator[];
  options: string[];
  required: boolean;
  sensitive: boolean;
  sortable: boolean;
  updatedAt: string;
};

/** One entry of the catalogue a client renders the "pick a kind" step from. */
export type UserAttributeKindOption = {
  availableControls: UserAttributeControl[];
  defaultControl: UserAttributeControl;
  kind: UserAttributeKind;
  operators: UserAttributeOperator[];
  requiresOptions: boolean;
  sortable: boolean;
  supportsMaxLength: boolean;
  supportsRange: boolean;
};

/** A stored value, as JSON carries it. */
export type UserAttributeValue = string | number | boolean | string[] | null;

/** One user's values, keyed by `<namespace>.<key>`. */
export type UserAttributeValues = Record<string, UserAttributeValue>;

/** The dialog opened from the Manage fields popover. */
export type UserFieldDialog =
  | { mode: 'create' }
  | { mode: 'edit'; attribute: UserAttribute }
  | { mode: 'delete'; attribute: UserAttribute };
