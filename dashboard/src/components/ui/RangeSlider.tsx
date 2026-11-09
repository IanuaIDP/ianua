'use client';

import type { CSSProperties, InputHTMLAttributes } from 'react';

import { cn } from '@/utils/cn';

type RangeSliderProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  'onChange' | 'type' | 'value'
> & {
  value: number;
  onValueChange: (value: number) => void;
};

export function RangeSlider({
  className,
  max = 100,
  min = 0,
  onValueChange,
  step = 1,
  value,
  ...props
}: RangeSliderProps) {
  const numericMin = Number(min);
  const numericMax = Number(max);
  const rawPercentage =
    numericMax > numericMin ? ((value - numericMin) / (numericMax - numericMin)) * 100 : 0;
  const percentage = Math.min(100, Math.max(0, rawPercentage));

  return (
    <input
      {...props}
      type="range"
      min={min}
      max={max}
      step={step}
      value={value}
      onChange={(event) => onValueChange(Number(event.target.value))}
      className={cn('range-slider', className)}
      style={
        {
          '--fill': `linear-gradient(to right, var(--primary) ${percentage}%, var(--text-border-gray) ${percentage}%)`,
        } as CSSProperties
      }
    />
  );
}
