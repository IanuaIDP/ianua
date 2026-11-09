'use client';

import type { ReactNode } from 'react';
import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

import { cn } from '@/utils/cn';

type TableCellTextProps = {
  children: ReactNode;
  className?: string;
  tooltip?: string;
};

export function TableCellText({ children, className, tooltip }: TableCellTextProps) {
  const content = tooltip ?? (typeof children === 'string' ? children : undefined);
  const textRef = useRef<HTMLSpanElement>(null);
  const [isTruncated, setIsTruncated] = useState(false);
  const [tooltipPosition, setTooltipPosition] = useState<{
    bottom: number;
    left?: number;
    right?: number;
  } | null>(null);

  useEffect(() => {
    const element = textRef.current;

    if (!element) {
      return;
    }

    const observedElement = element;

    function updateIsTruncated() {
      setIsTruncated(observedElement.scrollWidth > observedElement.clientWidth);
    }

    updateIsTruncated();

    const resizeObserver = new ResizeObserver(updateIsTruncated);
    resizeObserver.observe(observedElement);

    return () => resizeObserver.disconnect();
  }, [children]);

  function showTooltip() {
    const element = textRef.current;

    if (!element || !content || !isTruncated) {
      return;
    }

    const rect = element.getBoundingClientRect();
    const isRightAligned = rect.left + rect.width / 2 > window.innerWidth / 2;

    setTooltipPosition({
      bottom: window.innerHeight - rect.top + 8,
      ...(isRightAligned ? { right: window.innerWidth - rect.right } : { left: rect.left }),
    });
  }

  function hideTooltip() {
    setTooltipPosition(null);
  }

  return (
    <>
      <span
        ref={textRef}
        onBlur={hideTooltip}
        onFocus={showTooltip}
        onMouseEnter={showTooltip}
        onMouseLeave={hideTooltip}
        className={cn('block truncate', className)}
      >
        {children}
      </span>
      {content && tooltipPosition
        ? createPortal(
            <span
              role="tooltip"
              className="pointer-events-none fixed z-50 max-w-80 rounded-lg bg-white px-2.5 py-2 text-xs font-medium text-black opacity-100 shadow-lg"
              style={tooltipPosition}
            >
              {content}
            </span>,
            document.body,
          )
        : null}
    </>
  );
}

type TableCellStackProps = {
  primary: ReactNode;
  primaryClassName?: string;
  primaryTooltip?: string;
  secondary: ReactNode;
  secondaryClassName?: string;
  secondaryTooltip?: string;
};

export function TableCellStack({
  primary,
  primaryClassName,
  primaryTooltip,
  secondary,
  secondaryClassName,
  secondaryTooltip,
}: TableCellStackProps) {
  return (
    <span className="block min-w-0">
      <TableCellText className={primaryClassName} tooltip={primaryTooltip}>
        {primary}
      </TableCellText>
      <TableCellText className={secondaryClassName} tooltip={secondaryTooltip}>
        {secondary}
      </TableCellText>
    </span>
  );
}
