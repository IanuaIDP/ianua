'use client';

import { useEffect, useState } from 'react';

export function useActiveHelpSection(
  sectionIds: string[],
  scrollContainerId: string,
): [string, (id: string) => void] {
  const [activeId, setActiveId] = useState(sectionIds[0] ?? '');

  useEffect(() => {
    const scrollRoot = document.getElementById(scrollContainerId);
    const sections = sectionIds
      .map((id) => document.getElementById(id))
      .filter((section): section is HTMLElement => Boolean(section));

    if (!scrollRoot || sections.length === 0) {
      return;
    }

    const zoneTop = 96;
    let frameId: number;
    let lastScrollTop = -1;

    function computeActiveId(): string {
      const distanceFromBottom =
        scrollRoot!.scrollHeight - scrollRoot!.scrollTop - scrollRoot!.clientHeight;

      if (distanceFromBottom < 2) {
        return sections[sections.length - 1].id;
      }

      const containerRect = scrollRoot!.getBoundingClientRect();
      const zoneTopAbs = containerRect.top + zoneTop;
      const zoneBottomAbs = containerRect.top + containerRect.height * 0.5;

      const overlapping = sections.find((section) => {
        const rect = section.getBoundingClientRect();

        return rect.top < zoneBottomAbs && rect.bottom > zoneTopAbs;
      });

      if (overlapping) {
        return overlapping.id;
      }

      let fallback = sections[0].id;

      for (const section of sections) {
        const relativeTop = section.getBoundingClientRect().top - containerRect.top;

        if (relativeTop <= zoneTop) {
          fallback = section.id;
        } else {
          break;
        }
      }

      return fallback;
    }

    function tick() {
      const currentScrollTop = scrollRoot!.scrollTop;

      if (currentScrollTop !== lastScrollTop) {
        lastScrollTop = currentScrollTop;
        setActiveId(computeActiveId());
      }

      frameId = window.requestAnimationFrame(tick);
    }

    frameId = window.requestAnimationFrame(tick);

    return () => {
      window.cancelAnimationFrame(frameId);
    };
  }, [scrollContainerId, sectionIds]);

  return [activeId, setActiveId];
}
