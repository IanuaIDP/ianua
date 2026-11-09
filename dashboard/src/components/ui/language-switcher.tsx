'use client';

import { useCallback, useState } from 'react';
import {
  autoUpdate,
  flip,
  FloatingPortal,
  offset,
  shift,
  useClick,
  useDismiss,
  useFloating,
  useInteractions,
  useRole,
} from '@floating-ui/react';
import type { Placement } from '@floating-ui/react';
import { useLocale, useTranslations } from 'next-intl';

import { LOCALES, LOCALE_NATIVE_NAMES } from '@/i18n/config';
import type { AppLocale } from '@/i18n/config';
import { useChangeLanguage } from '@/hooks/i18n/use-change-language';
import { cn } from '@/utils/cn';

type LanguageSwitcherProps = {
  className?: string;
  placement?: Placement;
  /** `pill` shows the language code next to the icon; `icon` shows the icon only. */
  variant?: 'icon' | 'pill';
};

export function LanguageSwitcher({
  className,
  placement = 'bottom-end',
  variant = 'pill',
}: LanguageSwitcherProps) {
  const t = useTranslations('language');
  const currentLocale = useLocale();
  const { changeLanguage, isPending } = useChangeLanguage();
  const [isOpen, setIsOpen] = useState(false);

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(8), flip(), shift({ padding: 8 })],
    onOpenChange: setIsOpen,
    open: isOpen,
    placement,
    whileElementsMounted: autoUpdate,
  });

  const click = useClick(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getFloatingProps, getReferenceProps } = useInteractions([click, dismiss, role]);
  const setReferenceNode = useCallback(
    (node: HTMLButtonElement | null) => {
      refs.setReference(node);
    },
    [refs],
  );
  const setFloatingNode = useCallback(
    (node: HTMLDivElement | null) => {
      refs.setFloating(node);
    },
    [refs],
  );

  function handleSelect(locale: AppLocale) {
    setIsOpen(false);

    if (locale !== currentLocale) {
      void changeLanguage(locale);
    }
  }

  return (
    <>
      <button
        ref={setReferenceNode}
        type="button"
        aria-label={t('switcherAriaLabel')}
        aria-expanded={isOpen}
        disabled={isPending}
        className={cn(
          'flex items-center justify-center gap-1.5 text-white/80 transition-colors duration-200 hover:text-primary disabled:cursor-not-allowed disabled:opacity-60',
          variant === 'pill'
            ? 'h-9 rounded-md border border-borderGray px-2.5 text-xs font-semibold uppercase'
            : 'size-8 shrink-0 rounded-md text-textGray hover:text-white',
          className,
        )}
        {...getReferenceProps()}
      >
        <span className="material-symbols-rounded" aria-hidden="true">
          language
        </span>
        {variant === 'pill' ? currentLocale : null}
      </button>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className="z-110"
            {...getFloatingProps()}
          >
            <div className="grid min-w-40 gap-0.5 rounded-xl bg-borderGray p-1 shadow-dropdown">
              {LOCALES.map((locale) => (
                <button
                  key={locale}
                  type="button"
                  role="menuitemradio"
                  aria-checked={locale === currentLocale}
                  onClick={() => handleSelect(locale)}
                  className={cn(
                    'flex items-center justify-between gap-4 whitespace-nowrap rounded-lg px-3 py-2 text-left text-xs font-semibold text-white transition hover:bg-hoverBg',
                    locale === currentLocale && 'text-primary',
                  )}
                >
                  {LOCALE_NATIVE_NAMES[locale]}
                  {locale === currentLocale ? (
                    <span className="material-symbols-rounded" aria-hidden="true">
                      check
                    </span>
                  ) : null}
                </button>
              ))}
            </div>
          </div>
        </FloatingPortal>
      ) : null}
    </>
  );
}
