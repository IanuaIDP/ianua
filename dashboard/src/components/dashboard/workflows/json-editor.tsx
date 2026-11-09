'use client';

import { useTranslations } from 'next-intl';

import { Textarea } from '@/components/ui/Textarea';

type JsonEditorProps = {
  error?: string;
  id: string;
  label: string;
  onChange: (value: string) => void;
  value: string;
};

/** Reads a JSON object out of `text`. Empty text is an empty object. */
export function parseJsonObject(text: string): Record<string, unknown> | null {
  if (!text.trim()) {
    return {};
  }

  try {
    const value = JSON.parse(text) as unknown;

    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** A text box that must hold a JSON object, for data a person gives a run. */
export function JsonEditor({ error, id, label, onChange, value }: JsonEditorProps) {
  const t = useTranslations('dashboard.workflows.jsonEditor');

  return (
    <Textarea
      className="min-h-32 font-mono text-xs"
      containerClassName="mb-0"
      error={error}
      hint={t('hint')}
      id={id}
      label={label}
      onChange={(event) => onChange(event.target.value)}
      placeholder={'{\n  "amount": 12\n}'}
      value={value}
    />
  );
}
