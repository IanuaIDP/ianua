'use client';

import { useEffect, useState } from 'react';

import { LANDING_NAV_ITEMS } from '@/constants/landing';

/**
 * Tracks which landing page section is currently scrolled into the "active"
 * band near the top of the viewport, so the header nav can highlight the
 * matching link. Mirrors a standard scroll-spy: shrink the observed area to
 * a strip just below the sticky header and pick the topmost section that's
 * still intersecting it.
 */
export function useActiveLandingSection() {
  const [activeHref, setActiveHref] = useState<string>(LANDING_NAV_ITEMS[0]?.href ?? '');

  useEffect(() => {
    const scrollRoot = document.getElementById('landing-scroll-container');
    const sections = LANDING_NAV_ITEMS.map((item) =>
      document.getElementById(item.href.slice(1)),
    ).filter((section): section is HTMLElement => Boolean(section));

    if (sections.length === 0) {
      return;
    }

    const visibleIds = new Set<string>();

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            visibleIds.add(entry.target.id);
          } else {
            visibleIds.delete(entry.target.id);
          }
        }

        const topmostVisible = sections.find((section) => visibleIds.has(section.id));

        if (topmostVisible) {
          setActiveHref(`#${topmostVisible.id}`);
        }
      },
      { root: scrollRoot, rootMargin: '-96px 0px -70% 0px', threshold: 0 },
    );

    sections.forEach((section) => observer.observe(section));

    return () => observer.disconnect();
  }, []);

  return activeHref;
}
