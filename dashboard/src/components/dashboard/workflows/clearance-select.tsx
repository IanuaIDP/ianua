'use client';

import { useTranslations } from 'next-intl';

import { Select } from '@/components/ui/Select';
import type { ExposureLevel } from '@/types/workflows';

export const EXPOSURE_LEVELS: ExposureLevel[] = [
  'public',
  'internal',
  'confidential',
  'restricted',
];

type ClearanceSelectProps = {
  label: string;
  onChange: (value: ExposureLevel) => void;
  value: ExposureLevel;
};

/** Picks how sensitive the data given to a run is. */
export function ClearanceSelect({ label, onChange, value }: ClearanceSelectProps) {
  const t = useTranslations('dashboard.workflows.exposure');

  return (
    <Select
      containerClassName="mb-0"
      label={label}
      onChange={(next) => onChange(next as ExposureLevel)}
      options={EXPOSURE_LEVELS.map((level) => ({ label: t(level), value: level }))}
      value={value}
    />
  );
}
