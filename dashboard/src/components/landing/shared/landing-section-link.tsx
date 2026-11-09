'use client';

import type { MouseEvent, ReactNode } from 'react';
import Link from 'next/link';

type LandingSectionLinkProps = {
  children: ReactNode;
  className?: string;
  href: string;
  onClick?: () => void;
};

export function LandingSectionLink({
  children,
  className,
  href,
  onClick,
}: LandingSectionLinkProps) {
  const handleSectionClick = (event: MouseEvent<HTMLAnchorElement>) => {
    const section = document.querySelector(href);

    if (!section) {
      onClick?.();
      return;
    }

    event.preventDefault();
    window.history.pushState(null, '', href);

    const scrollToSection = () => {
      const scrollContainer = document.getElementById('landing-scroll-container');
      const headerOffset = scrollContainer ? 24 : 88;
      const sectionTop =
        section.getBoundingClientRect().top +
        (scrollContainer?.scrollTop ?? window.scrollY) -
        (scrollContainer?.getBoundingClientRect().top ?? 0);

      const scrollTarget = scrollContainer ?? window;

      scrollTarget.scrollTo({
        top: Math.max(sectionTop - headerOffset, 0),
        behavior: 'smooth',
      });
    };

    onClick?.();

    if (onClick) {
      window.requestAnimationFrame(() => {
        window.requestAnimationFrame(scrollToSection);
      });
      return;
    }

    scrollToSection();
  };

  return (
    <Link href={href} onClick={handleSectionClick} className={className}>
      {children}
    </Link>
  );
}
