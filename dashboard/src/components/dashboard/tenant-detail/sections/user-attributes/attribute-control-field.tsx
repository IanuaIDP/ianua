'use client';

import { useLocale, useTranslations } from 'next-intl';

import { Checkbox } from '@/components/ui/Checkbox';
import { ColourPicker } from '@/components/ui/ColourPicker';
import { DayInput } from '@/components/ui/day-input';
import { Input } from '@/components/ui/Input';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { RadioGroup } from '@/components/ui/RadioGroup';
import { RangeSlider } from '@/components/ui/RangeSlider';
import { Select } from '@/components/ui/Select';
import { StarRating } from '@/components/ui/StarRating';
import { Switch } from '@/components/ui/Switch';
import { TagInput } from '@/components/ui/TagInput';
import { Textarea } from '@/components/ui/Textarea';
import { getCountryOptions } from '@/constants/countries';
import type { UserAttribute, UserAttributeValue } from '@/types/user-attribute';
import { cn } from '@/utils/cn';

type AttributeControlFieldProps = {
  attribute: UserAttribute;
  className?: string;
  disabled?: boolean;
  error?: string;
  onChange: (value: UserAttributeValue) => void;
  value: UserAttributeValue;
};

const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

/**
 * Renders the control a declared field asks for.
 *
 * The field's `control` decides the widget and nothing else — it is a
 * presentation hint, and the API validates against the field's *kind*
 * regardless of what was rendered. Which is why the `default` arm below is a
 * text box rather than a thrown error: a control this build does not know yet
 * still has to be fillable.
 */
export function AttributeControlField({
  attribute,
  className,
  disabled = false,
  error,
  onChange,
  value,
}: AttributeControlFieldProps) {
  const t = useTranslations('dashboard.userFields');
  const locale = useLocale();
  const label = attribute.displayName + (attribute.required ? ' *' : '');
  const hint = attribute.description;
  const shared = {
    className: className ?? fieldClassName,
    containerClassName: fieldContainerClassName,
    disabled,
    error,
    hint,
    label,
  };
  const options = attribute.options.map((option) => ({ label: option, value: option }));

  switch (attribute.control) {
    case 'text_area':
      return (
        <Textarea
          {...shared}
          maxLength={attribute.maxLength}
          value={asText(value)}
          onChange={(event) => onChange(event.target.value)}
        />
      );

    case 'number_input':
    case 'currency_input':
    case 'percent_input':
      return (
        <Input
          {...shared}
          className={cn(shared.className, 'tabular-nums')}
          type="number"
          inputMode="decimal"
          max={attribute.maximum}
          min={attribute.minimum}
          step={stepFor(attribute.kind)}
          placeholder={placeholderFor(attribute.control)}
          value={asText(value)}
          onChange={(event) => onChange(asNumber(event.target.value))}
        />
      );

    case 'slider':
      return (
        <RangeSlider
          {...shared}
          max={attribute.maximum ?? 100}
          min={attribute.minimum ?? 0}
          value={typeof value === 'number' ? value : (attribute.minimum ?? 0)}
          onValueChange={(next) => onChange(next)}
        />
      );

    case 'toggle':
      return (
        <Switch
          checked={value === true}
          className={fieldContainerClassName}
          description={hint}
          disabled={disabled}
          label={label}
          onCheckedChange={onChange}
        />
      );

    case 'checkbox':
      return (
        <Checkbox
          checked={value === true}
          containerClassName={fieldContainerClassName}
          disabled={disabled}
          error={error}
          label={label}
          onChange={(event) => onChange(event.target.checked)}
        />
      );

    case 'select':
      return (
        <Select
          {...shared}
          options={options}
          value={asText(value)}
          onChange={(next) => onChange(next || null)}
        />
      );

    case 'country_select':
      return (
        <Select
          {...shared}
          options={getCountryOptions(locale)}
          placeholder={t('selectCountry')}
          value={asText(value)}
          onChange={(next) => onChange(next || null)}
        />
      );

    case 'radio_group':
      return (
        <RadioGroup
          {...shared}
          name={`${attribute.namespace}.${attribute.key}`}
          options={options}
          value={asText(value)}
          onChange={(next) => onChange(next || null)}
        />
      );

    case 'multi_select':
      return (
        <MultiSelect
          {...shared}
          options={options}
          value={asList(value)}
          onChange={(next) => onChange(next)}
        />
      );

    case 'checkbox_group':
      return (
        <div className={fieldContainerClassName}>
          <p className="mb-1.5 text-xs font-medium text-textGray">{label}</p>
          <div className="flex flex-col gap-1.5">
            {attribute.options.map((option) => {
              const selected = asList(value);

              return (
                <Checkbox
                  key={option}
                  checked={selected.includes(option)}
                  disabled={disabled}
                  label={option}
                  onChange={(event) =>
                    onChange(
                      event.target.checked
                        ? [...selected, option]
                        : selected.filter((entry) => entry !== option),
                    )
                  }
                />
              );
            })}
          </div>
          {error ? <p className="mt-1.5 text-xs font-medium text-error">{error}</p> : null}
          {!error && hint ? (
            <p className="mt-1.5 text-xs font-medium text-textGray">{hint}</p>
          ) : null}
        </div>
      );

    case 'tag_input':
      return (
        <TagInput
          {...shared}
          maxLength={attribute.maxLength}
          value={asList(value)}
          onChange={(next) => onChange(next)}
        />
      );

    case 'date_picker':
      return (
        <DayInput {...shared} value={asText(value)} onChange={(next) => onChange(next || null)} />
      );

    case 'date_time_picker':
      return (
        <DayInput
          {...shared}
          withTime
          placeholder="dd.mm.yyyy hh:mm"
          value={asText(value)}
          onChange={(next) => onChange(next || null)}
        />
      );

    case 'colour_picker':
      return (
        <ColourPicker
          {...shared}
          value={asText(value)}
          onChange={(next) => onChange(next || null)}
        />
      );

    case 'star_rating':
      return (
        <StarRating
          {...shared}
          value={typeof value === 'number' ? value : null}
          onChange={(next) => onChange(next)}
        />
      );

    case 'email_input':
    case 'phone_input':
    case 'url_input':
    case 'text_input':
    default:
      return (
        <Input
          {...shared}
          type={inputTypeFor(attribute.control)}
          maxLength={attribute.maxLength}
          placeholder={placeholderFor(attribute.control)}
          value={asText(value)}
          onChange={(event) => onChange(event.target.value)}
        />
      );
  }
}

/** An amount stops at its cents; a count and a rating have none to give. */
function stepFor(kind: UserAttribute['kind']) {
  if (kind === 'whole_number' || kind === 'rating') {
    return 1;
  }

  if (kind === 'money') {
    return 0.01;
  }

  return 'any';
}

function inputTypeFor(control: UserAttribute['control']) {
  if (control === 'email_input') {
    return 'email';
  }

  if (control === 'phone_input') {
    return 'tel';
  }

  if (control === 'url_input') {
    return 'url';
  }

  return 'text';
}

function placeholderFor(control: UserAttribute['control']) {
  switch (control) {
    case 'currency_input':
      return '45000';
    case 'percent_input':
      return '20';
    case 'email_input':
      return 'name@example.com';
    case 'phone_input':
      return '+31 6 12345678';
    case 'url_input':
      return 'https://example.com';
    default:
      return undefined;
  }
}

function asText(value: UserAttributeValue) {
  if (value === null || value === undefined) {
    return '';
  }

  return Array.isArray(value) ? value.join(', ') : String(value);
}

function asList(value: UserAttributeValue) {
  return Array.isArray(value) ? value : [];
}

/** Keeps a half-typed number out of the payload without wiping the field. */
function asNumber(value: string): UserAttributeValue {
  if (!value.trim()) {
    return null;
  }

  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : null;
}
