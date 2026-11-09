'use client';

import { Input } from '@/components/ui/Input';

const MICROS_PER_UNIT = 1_000_000;

type MoneyInputProps = {
  disabled: boolean;
  hint?: string;
  label: string;
  onChange: (micros: number | undefined) => void;
  placeholder?: string;
  value: number | undefined;
};

/** Whole units of the tenant's billing currency on screen, millionths on the wire. */
export function MoneyInput({
  disabled,
  hint,
  label,
  onChange,
  placeholder,
  value,
}: MoneyInputProps) {
  return (
    <Input
      containerClassName="mb-0"
      disabled={disabled}
      hint={hint}
      label={label}
      min={0}
      onChange={(event) =>
        onChange(
          event.target.value === ''
            ? undefined
            : Math.round(Number(event.target.value) * MICROS_PER_UNIT),
        )
      }
      placeholder={placeholder}
      step="any"
      type="number"
      value={value === undefined ? '' : String(value / MICROS_PER_UNIT)}
    />
  );
}
