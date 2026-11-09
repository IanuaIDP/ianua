'use client';

import { useRef } from 'react';
import { useTranslations } from 'next-intl';

import { cn } from '@/utils/cn';

type WasmModuleFieldProps = {
  error?: string;
  fileName: string;
  isDisabled: boolean;
  isUploading: boolean;
  moduleRef: string;
  onSelect: (file: File) => void;
};

/**
 * Picks and uploads the WebAssembly module a `Custom` stage runs.
 *
 * The upload happens on selection rather than on submit, because the stage
 * references the module by the hash the upload returns - there is nothing to
 * submit until the module is stored. Uploading creates no stage on its own.
 */
export function WasmModuleField({
  error,
  fileName,
  isDisabled,
  isUploading,
  moduleRef,
  onSelect,
}: WasmModuleFieldProps) {
  const t = useTranslations('dashboard.pipelines.addStage.module');
  const inputRef = useRef<HTMLInputElement>(null);

  function handleChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];

    if (file) {
      onSelect(file);
    }

    event.target.value = '';
  }

  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs font-semibold text-white">{t('title')}</span>

      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={isDisabled || isUploading}
          onClick={() => inputRef.current?.click()}
          className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-borderGray bg-cardBg px-3 text-xs font-semibold text-white transition hover:border-white/20 disabled:pointer-events-none disabled:opacity-60"
        >
          <span className="material-symbols-rounded text-base!" aria-hidden>
            upload_file
          </span>
          {fileName ? t('replace') : t('choose')}
        </button>
        <span
          className={cn(
            'min-w-0 flex-1 truncate text-xs',
            fileName ? 'text-white' : 'text-textGray',
          )}
        >
          {fileName || t('noFile')}
        </span>
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".wasm,.wat,application/wasm"
        className="hidden"
        onChange={handleChange}
      />

      {isUploading ? (
        <p className="text-xs text-textGray">{t('uploading')}</p>
      ) : error ? (
        <p className="text-xs text-error">{error}</p>
      ) : moduleRef ? (
        <p className="truncate text-xs text-textGray">
          {t.rich('stored', {
            ref: moduleRef,
            value: (chunks) => <span className="text-white">{chunks}</span>,
          })}
        </p>
      ) : (
        <p className="text-xs text-textGray">{t('hint')}</p>
      )}
    </div>
  );
}
