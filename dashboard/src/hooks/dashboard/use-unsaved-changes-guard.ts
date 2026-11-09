'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export type UnsavedChangesGuard = {
  /** Where the person asked to go while the form was unsaved. */
  pendingHref: string | null;
  /** Goes to `href`, asking first when there are unsaved changes. */
  leaveTo: (href: string) => void;
  confirmLeave: () => void;
  stay: () => void;
};

/**
 * Asks before leaving a form that has unsaved changes: a closing tab or a
 * reload through the browser's own prompt, any in-app link through the
 * `UnsavedChangesModal` the form renders with this guard.
 */
export function useUnsavedChangesGuard(isDirty: boolean): UnsavedChangesGuard {
  const router = useRouter();
  const [pendingHref, setPendingHref] = useState<string | null>(null);

  useEffect(() => {
    if (!isDirty) {
      return;
    }

    function warnBeforeUnload(event: BeforeUnloadEvent) {
      event.preventDefault();
    }

    function interceptLinkClick(event: MouseEvent) {
      const anchor = (event.target as HTMLElement | null)?.closest?.('a[href]');

      if (!(anchor instanceof HTMLAnchorElement) || anchor.target === '_blank') {
        return;
      }

      if (event.metaKey || event.ctrlKey || event.shiftKey) {
        return;
      }

      event.preventDefault();
      event.stopImmediatePropagation();
      setPendingHref(anchor.getAttribute('href'));
    }

    window.addEventListener('beforeunload', warnBeforeUnload);
    document.addEventListener('click', interceptLinkClick, true);

    return () => {
      window.removeEventListener('beforeunload', warnBeforeUnload);
      document.removeEventListener('click', interceptLinkClick, true);
    };
  }, [isDirty]);

  function leaveTo(href: string) {
    if (isDirty) {
      setPendingHref(href);
      return;
    }

    router.push(href);
  }

  function confirmLeave() {
    if (pendingHref) {
      router.push(pendingHref);
    }

    setPendingHref(null);
  }

  return { confirmLeave, leaveTo, pendingHref, stay: () => setPendingHref(null) };
}
