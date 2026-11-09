'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';

import { cn } from '@/utils/cn';

type ScrollRevealProps = {
  children: ReactNode;
  className?: string;
  delayMs?: number;
};

export function ScrollReveal({ children, className, delayMs = 0 }: ScrollRevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const element = ref.current;

    if (!element) {
      return;
    }

    const scrollRoot = document.getElementById('landing-scroll-container');
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { root: scrollRoot, threshold: 0.18, rootMargin: '0px 0px -80px' },
    );

    observer.observe(element);

    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={cn(
        'transform-gpu transition duration-700 ease-out motion-reduce:translate-y-0 motion-reduce:opacity-100',
        isVisible ? 'translate-y-0 opacity-100' : 'translate-y-8 opacity-0',
        className,
      )}
      style={{ transitionDelay: `${delayMs}ms` }}
    >
      {children}
    </div>
  );
}
