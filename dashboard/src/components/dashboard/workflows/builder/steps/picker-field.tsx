'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  getApiErrorMessage,
  getMemories,
  getWorkflowApps,
  getWorkflowDataTargets,
  getWorkflowPickerChoices,
} from '@/lib/api';
import { cn } from '@/utils/cn';

export type PickerTarget = {
  accountId: string | null;
  dependsOn: { label: string; value: unknown } | null;
  input: string;
  integration: string;
  operation: string;
};

type PickerFieldProps = {
  disabled: boolean;
  example?: string;
  isMulti: boolean;
  label: string;
  onChange: (value: unknown) => void;
  target: PickerTarget;
  value: unknown;
};

function toValues(value: unknown) {
  return Array.isArray(value) ? value.map(String) : [];
}

function TypedValue({
  disabled,
  example,
  hint,
  isMulti,
  label,
  onChange,
  value,
}: Omit<PickerFieldProps, 'target'> & { hint: string }) {
  return (
    <>
      <Input
        aria-label={label}
        containerClassName="mb-0"
        disabled={disabled}
        onChange={(event) =>
          onChange(
            isMulti
              ? event.target.value
                  .split(',')
                  .map((item) => item.trim())
                  .filter(Boolean)
              : event.target.value,
          )
        }
        placeholder={example}
        value={isMulti ? toValues(value).join(', ') : typeof value === 'string' ? value : ''}
      />
      <p className="mt-1.5 text-xs text-textGray">{hint}</p>
    </>
  );
}

/** Fills a picker from the service through the step's account, or lets the person type it. */
export function PickerField(props: PickerFieldProps) {
  const t = useTranslations('dashboard.workflowBuilder.pickerField');
  const { orgSlug, tenantSlug } = useBuilderContext();
  const { disabled, isMulti, label, onChange, target, value } = props;
  const needsParent = target.dependsOn && !target.dependsOn.value;
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && target.accountId) && !needsParent,
    queryFn: () =>
      getWorkflowPickerChoices(orgSlug ?? '', tenantSlug, target, {
        accountId: target.accountId ?? '',
        dependsOn: target.dependsOn?.value,
      }),
    queryKey: [
      'workflow-picker',
      orgSlug,
      tenantSlug,
      target.integration,
      target.operation,
      target.input,
      target.accountId,
      target.dependsOn?.value,
    ],
    retry: false,
  });

  if (!target.accountId) {
    return <TypedValue {...props} hint={t('pickAccountFirst')} />;
  }

  if (needsParent) {
    return <TypedValue {...props} hint={t('setFirst', { field: target.dependsOn?.label ?? '' })} />;
  }

  if (isLoading) {
    return <p className="text-xs text-textGray">{t('loading')}</p>;
  }

  if (error) {
    return <TypedValue {...props} hint={getApiErrorMessage(error, t('cannotRead'))} />;
  }

  if (!data || data.unavailable !== null || data.choices.length === 0) {
    return <TypedValue {...props} hint={data?.unavailable ?? t('nothingListed')} />;
  }

  if (isMulti) {
    const selected = toValues(value);

    return (
      <div className="flex flex-wrap gap-1.5">
        {data.choices.map((choice) => {
          const isOn = selected.includes(choice.value);

          return (
            <button
              key={choice.value}
              type="button"
              aria-pressed={isOn}
              disabled={disabled}
              onClick={() =>
                onChange(
                  isOn
                    ? selected.filter((item) => item !== choice.value)
                    : [...selected, choice.value],
                )
              }
              className={cn(
                'rounded-full px-3 py-1 text-xs font-medium',
                isOn ? 'bg-primary/15 text-primary' : 'bg-surfaceChip text-textGray',
              )}
            >
              {choice.label}
            </button>
          );
        })}
      </div>
    );
  }

  const current = typeof value === 'string' ? value : '';
  const options =
    data.choices.some((choice) => choice.value === current) || !current
      ? data.choices
      : [{ label: current, value: current }, ...data.choices];

  return (
    <Select
      containerClassName="mb-0"
      disabled={disabled}
      onChange={onChange}
      options={options}
      placeholder={label}
      value={current}
    />
  );
}

type TargetPickerProps = {
  block: 'app_picker' | 'data_picker' | 'memory_picker';
  disabled: boolean;
  label: string;
  onChange: (value: string) => void;
  value: unknown;
};

const TARGET_LINKS = {
  app_picker: 'routes',
  data_picker: 'routes',
  memory_picker: 'memories',
};

/** Picks one of the tenant's own apps, data systems or memories, by its id. */
export function TargetPicker({ block, disabled, label, onChange, value }: TargetPickerProps) {
  const t = useTranslations('dashboard.workflowBuilder.pickerField');
  const { orgSlug, tenantPathFor, tenantSlug } = useBuilderContext();
  const { data, isLoading } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => {
      const slug = orgSlug ?? '';

      if (block === 'app_picker') {
        return getWorkflowApps(slug, tenantSlug);
      }

      return block === 'data_picker'
        ? getWorkflowDataTargets(slug, tenantSlug)
        : getMemories(slug, tenantSlug);
    },
    queryKey: ['workflow-target-picker', block, orgSlug, tenantSlug],
  });

  if (isLoading) {
    return <p className="text-xs text-textGray">{t('loading')}</p>;
  }

  if (!data || data.length === 0) {
    return (
      <Link
        href={tenantPathFor(TARGET_LINKS[block])}
        className="text-xs font-semibold text-primary hover:underline"
      >
        {block === 'memory_picker' ? t('noMemories') : t('noneOpen')}
      </Link>
    );
  }

  return (
    <Select
      containerClassName="mb-0"
      disabled={disabled}
      onChange={onChange}
      options={data.map((item) => ({ label: item.name, value: item.id }))}
      placeholder={label}
      value={typeof value === 'string' ? value : ''}
    />
  );
}
