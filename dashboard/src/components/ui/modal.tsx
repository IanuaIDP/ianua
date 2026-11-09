'use client';

import {
  Children,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from 'react';
import { useTranslations } from 'next-intl';

function hasRenderableChildren(children: ReactNode) {
  return Children.toArray(children).length > 0;
}
import { createPortal } from 'react-dom';

import { Button } from '@/components/ui/Button';
import { cn } from '@/utils/cn';

type ModalSize = 'sm' | 'md' | 'lg' | 'xl';

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  autoFocus?: boolean;
  title?: string;
  description?: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
  size?: ModalSize;
  showCloseButton?: boolean;
  /** Whether Escape closes the dialog. Set to false for secrets shown once. */
  dismissible?: boolean;
  primaryActionLabel?: string;
  onPrimaryAction?: () => void;
  primaryActionType?: 'button' | 'submit';
  primaryActionForm?: string;
  isPrimaryActionDisabled?: boolean;
  isPrimaryActionLoading?: boolean;
  secondaryActionLabel?: string;
  onSecondaryAction?: () => void;
  showCancelButton?: boolean;
}

const modalSizeClasses: Record<ModalSize, string> = {
  sm: 'max-w-[400px]',
  md: 'max-w-[400px]',
  lg: 'max-w-[400px]',
  xl: 'max-w-[760px]',
};

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export function Modal({
  open,
  onClose,
  autoFocus = true,
  title,
  description,
  icon,
  children,
  size = 'md',
  showCloseButton = true,
  dismissible = true,
  primaryActionLabel,
  onPrimaryAction,
  primaryActionType = 'button',
  primaryActionForm,
  isPrimaryActionDisabled = false,
  isPrimaryActionLoading = false,
  secondaryActionLabel,
  onSecondaryAction,
  showCancelButton = true,
}: ModalProps) {
  const t = useTranslations('common');
  const titleId = useId();
  const descriptionId = useId();
  const modalRef = useRef<HTMLDivElement>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
  const [shouldRender, setShouldRender] = useState(open);
  const [isVisible, setIsVisible] = useState(false);

  function getFocusableElements() {
    return Array.from(modalRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? []);
  }

  useEffect(() => {
    let animationFrameId: number | undefined;
    let timeoutId: number | undefined;

    if (open) {
      animationFrameId = window.requestAnimationFrame(() => setShouldRender(true));
    } else {
      animationFrameId = window.requestAnimationFrame(() => setIsVisible(false));
      timeoutId = window.setTimeout(() => setShouldRender(false), 200);
    }

    return () => {
      if (animationFrameId) {
        window.cancelAnimationFrame(animationFrameId);
      }

      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [open]);

  useEffect(() => {
    if (!shouldRender || !open) {
      return;
    }

    const animationFrameId = window.requestAnimationFrame(() => setIsVisible(true));

    return () => window.cancelAnimationFrame(animationFrameId);
  }, [open, shouldRender]);

  useEffect(() => {
    if (!shouldRender) {
      return;
    }

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, [shouldRender]);

  useEffect(() => {
    if (!open || !shouldRender) {
      return;
    }

    previouslyFocusedElementRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const timeoutId = window.setTimeout(() => {
      const firstFocusableElement = autoFocus ? getFocusableElements()[0] : undefined;

      if (firstFocusableElement) {
        firstFocusableElement.focus();
      } else {
        modalRef.current?.focus();
      }
    }, 0);

    return () => {
      window.clearTimeout(timeoutId);
      previouslyFocusedElementRef.current?.focus();
    };
  }, [autoFocus, open, shouldRender]);

  if (!shouldRender) {
    return null;
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      event.stopPropagation();

      if (dismissible) {
        onClose();
      }

      return;
    }

    if (event.key !== 'Tab') {
      return;
    }

    const focusableElements = getFocusableElements();

    if (!focusableElements.length) {
      event.preventDefault();
      modalRef.current?.focus();
      return;
    }

    const firstFocusableElement = focusableElements[0];
    const lastFocusableElement = focusableElements[focusableElements.length - 1];

    if (event.shiftKey && document.activeElement === firstFocusableElement) {
      event.preventDefault();
      lastFocusableElement.focus();
    } else if (!event.shiftKey && document.activeElement === lastFocusableElement) {
      event.preventDefault();
      firstFocusableElement.focus();
    }
  }

  function handleBackdropMouseDown(event: MouseEvent<HTMLDivElement>) {
    if (event.target === event.currentTarget) {
      event.preventDefault();
    }
  }

  return createPortal(
    <div
      onMouseDown={handleBackdropMouseDown}
      className={cn(
        'fixed inset-0 z-50 flex items-center justify-center bg-appBg/90 px-4 backdrop-blur-sm transition-opacity duration-200 ease-out',
        isVisible ? 'opacity-100' : 'opacity-0',
      )}
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        onKeyDown={handleKeyDown}
        className={cn(
          'flex max-h-[85vh] w-full flex-col overflow-hidden rounded-xl border border-borderGray bg-cardBg shadow-lg transition-all duration-200 ease-out',
          modalSizeClasses[size],
          isVisible ? 'scale-100 opacity-100' : 'scale-95 opacity-0',
        )}
      >
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-6">
          {(title || description || icon || showCloseButton) && (
            <div
              className={cn(
                'flex items-start justify-between gap-4',
                hasRenderableChildren(children) ? 'mb-6' : 'mb-0',
              )}
            >
              <div className="flex min-w-0 items-center gap-4">
                {icon ? <div className="shrink-0">{icon}</div> : null}
                <div className="min-w-0">
                  {title ? (
                    <h2 id={titleId} className="text-base font-bold text-white">
                      {title}
                    </h2>
                  ) : null}
                  {description ? (
                    <p id={descriptionId} className="mt-2.5 text-xs text-textGray">
                      {description}
                    </p>
                  ) : null}
                </div>
              </div>

              {showCloseButton ? (
                <button
                  type="button"
                  aria-label={t('closeModal')}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={onClose}
                  className="flex size-8 shrink-0 items-center justify-center rounded-lg text-textGray transition hover:bg-hoverBg hover:text-white focus:outline-none focus-visible:border focus-visible:border-focus"
                >
                  <span className="material-symbols-rounded" aria-hidden>
                    close
                  </span>
                </button>
              ) : null}
            </div>
          )}

          {hasRenderableChildren(children) ? (
            <div className="flex flex-col gap-4">{children}</div>
          ) : null}
        </div>

        {primaryActionLabel ? (
          <div className="flex shrink-0 justify-end gap-2.5 border-t border-borderGray px-4 py-2.5">
            {showCancelButton ? (
              <Button
                type="button"
                variant="outline"
                onMouseDown={(event) => event.preventDefault()}
                onClick={onSecondaryAction ?? onClose}
                className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
              >
                {secondaryActionLabel ?? t('cancel')}
              </Button>
            ) : null}
            <Button
              type={primaryActionType}
              form={primaryActionForm}
              variant="focus"
              onClick={onPrimaryAction}
              isLoading={isPrimaryActionLoading}
              disabled={isPrimaryActionDisabled}
              className="w-auto px-4 py-1.5 text-sm font-medium tracking-normal"
            >
              {primaryActionLabel}
            </Button>
          </div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
