'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { DataPicker } from '@/components/dashboard/workflows/builder/steps/data-picker';
import { cn } from '@/utils/cn';

type PathFieldProps = {
  disabled: boolean;
  onChange: (path: string) => void;
  placeholder: string;
  stepKey: string;
  value: string;
};

/** Picks one path of earlier data, for a field that can only ever be a path. */
export function PathField({ disabled, onChange, placeholder, stepKey, value }: PathFieldProps) {
  const t = useTranslations('dashboard.workflowBuilder.picker');
  const [isPicking, setIsPicking] = useState(false);

  return (
    <div>
      <button
        type="button"
        aria-expanded={isPicking}
        aria-label={t('pickPath')}
        disabled={disabled}
        onClick={() => setIsPicking((current) => !current)}
        className={cn(
          'w-full truncate rounded-lg px-2.5 py-1.5 text-left text-xs',
          value ? 'bg-primary/15 text-primary' : 'bg-surfaceChip text-textGray',
        )}
      >
        {value || placeholder}
      </button>
      {isPicking && !disabled ? (
        <DataPicker
          onPick={(path) => {
            onChange(path);
            setIsPicking(false);
          }}
          stepKey={stepKey}
        />
      ) : null}
    </div>
  );
}
