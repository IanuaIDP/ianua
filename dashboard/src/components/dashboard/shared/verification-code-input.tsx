'use client';

import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import { useEffect, useRef, type ChangeEvent, type KeyboardEvent } from 'react';
import { useTranslations } from 'next-intl';

type VerificationCodeInputProps = {
  label?: string;
  length?: number;
  onChange: (value: string) => void;
  value: string;
};

export function VerificationCodeInput({
  label,
  length = VERIFICATION_CODE_LENGTH,
  onChange,
  value,
}: VerificationCodeInputProps) {
  const t = useTranslations('common.verificationCode');
  const inputRefs = useRef<Array<HTMLInputElement | null>>([]);
  const digits = Array.from({ length }, (_item, index) => value[index] ?? '');

  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  function setInputRef(index: number) {
    return (element: HTMLInputElement | null) => {
      inputRefs.current[index] = element;
    };
  }

  function updateDigit(index: number, digit: string) {
    const nextDigits = [...digits];
    nextDigits[index] = digit;
    onChange(nextDigits.join('').slice(0, length));
  }

  function handleCodeChange(index: number, event: ChangeEvent<HTMLInputElement>) {
    const nextDigit = event.target.value.replace(/\D/g, '').slice(-1);

    updateDigit(index, nextDigit);

    if (nextDigit && index < length - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  }

  function handleCodeKeyDown(index: number, event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  }

  return (
    <div>
      <p className="mb-4 text-xs font-medium text-textGray">{label ?? t('label', { length })}</p>
      <div
        className="grid gap-2.5"
        style={{ gridTemplateColumns: `repeat(${length}, minmax(0, 1fr))` }}
      >
        {digits.map((digit, index) => (
          <input
            key={index}
            ref={setInputRef(index)}
            aria-label={t('digitAriaLabel', { index: index + 1 })}
            inputMode="numeric"
            maxLength={1}
            value={digit}
            onChange={(event) => handleCodeChange(index, event)}
            onKeyDown={(event) => handleCodeKeyDown(index, event)}
            className="h-8 rounded-[10px] border border-borderGray bg-transparent text-center text-sm font-medium text-white outline-none transition focus:border-focus"
          />
        ))}
      </div>
    </div>
  );
}
