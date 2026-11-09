'use client';

import { useCallback, useState } from 'react';
import type { ReactNode } from 'react';
import {
  autoUpdate,
  flip,
  FloatingPortal,
  offset,
  safePolygon,
  shift,
  useDismiss,
  useFloating,
  useFocus,
  useHover,
  useInteractions,
  useRole,
  type Placement,
} from '@floating-ui/react';

import { cn } from '@/utils/cn';

type FloatingTooltipProps = {
  children: ReactNode;
  className?: string;
  content: ReactNode;
  disabled?: boolean;
  placement?: Placement;
  title?: string;
};

/**
 * Hover/focus tooltip built on floating-ui (same pattern as
 * RolePermissionsCell). Unlike the CSS-only `Tooltip` component, the
 * floating content is rendered via a portal, so it never contributes to
 * an ancestor's scrollable overflow and never gets clipped by a
 * scroll/overflow container — safe to use inside scrollable tables.
 */
export function FloatingTooltip({
  children,
  className,
  content,
  disabled = false,
  placement = 'top',
  title,
}: FloatingTooltipProps) {
  const [isOpen, setIsOpen] = useState(false);
  const isRich = Boolean(title);

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(8), flip(), shift({ padding: 8 })],
    onOpenChange: setIsOpen,
    open: isOpen,
    placement,
    whileElementsMounted: autoUpdate,
  });

  const hover = useHover(context, { enabled: !disabled, handleClose: safePolygon() });
  const focus = useFocus(context, { enabled: !disabled });
  const dismiss = useDismiss(context);
  const tooltipRole = useRole(context, { role: 'tooltip' });
  const { getFloatingProps, getReferenceProps } = useInteractions([
    hover,
    focus,
    dismiss,
    tooltipRole,
  ]);
  const setReferenceNode = useCallback(
    (node: HTMLSpanElement | null) => {
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

  if (disabled) {
    return <>{children}</>;
  }

  return (
    <>
      <span
        ref={setReferenceNode}
        tabIndex={0}
        className={cn('inline-flex outline-none', className)}
        {...getReferenceProps()}
      >
        {children}
      </span>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className={cn(
              'z-50 rounded-lg px-2.5 py-2 text-xs font-medium shadow-lg',
              isRich
                ? 'whitespace-normal border border-borderGray bg-appBg text-white'
                : 'whitespace-nowrap bg-white text-black',
            )}
            {...getFloatingProps()}
          >
            {title ? <span className="mb-1 block font-semibold text-white">{title}</span> : null}
            {content}
          </div>
        </FloatingPortal>
      ) : null}
    </>
  );
}
