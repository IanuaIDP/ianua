'use client';

import Image, { type StaticImageData } from 'next/image';
import { useEffect, useRef, useState } from 'react';
import { useTranslations } from 'next-intl';

import accessGrantedIcon from '@/assets/access-granted.svg';
import authenticateIcon from '@/assets/authenticate.svg';
import authenticationSuccessfulIcon from '@/assets/authentication-successful.svg';
import lockedIcon from '@/assets/locked.svg';
import openingIcon from '@/assets/opening.svg';
import { IndicatorState } from '@/types/landing';
import { cn } from '@/utils/cn';

type VisibleIndicatorState = Exclude<IndicatorState, 'hidden'>;

const statusMilestones: Array<{ id: string; state: VisibleIndicatorState }> = [
  { id: 'access-denied-line', state: 'locked' },
  { id: 'verifying-identity-line', state: 'authenticating' },
  { id: 'authentication-successful-line', state: 'authenticationSuccessful' },
  { id: 'opening-line', state: 'opening' },
  { id: 'access-granted-line', state: 'accessGranted' },
];

const statusContent: Record<
  VisibleIndicatorState,
  { icon: StaticImageData; tone: 'focus' | 'primary' }
> = {
  locked: {
    icon: lockedIcon,
    tone: 'focus',
  },
  authenticating: {
    icon: authenticateIcon,
    tone: 'focus',
  },
  authenticationSuccessful: {
    icon: authenticationSuccessfulIcon,
    tone: 'primary',
  },
  opening: {
    icon: openingIcon,
    tone: 'primary',
  },
  accessGranted: {
    icon: accessGrantedIcon,
    tone: 'primary',
  },
};

export function ScrollStatusIndicator() {
  const t = useTranslations('landing.statusIndicator');
  const indicatorRef = useRef<HTMLElement>(null);
  const [indicatorState, setIndicatorState] = useState<IndicatorState>('hidden');

  useEffect(() => {
    let animationFrame = 0;
    let currentState: IndicatorState = 'hidden';
    const scrollContainer = document.getElementById('landing-scroll-container');

    const updateState = () => {
      const indicatorElement = indicatorRef.current;
      const milestones = statusMilestones.map((milestone) => {
        const element = document.getElementById(milestone.id);
        const rect = element?.getBoundingClientRect();

        return {
          ...milestone,
          center: rect ? rect.top + rect.height / 2 : null,
        };
      });

      if (!indicatorElement || milestones.some((milestone) => milestone.center === null)) {
        if (currentState !== 'hidden') {
          currentState = 'hidden';
          setIndicatorState('hidden');
        }
        return;
      }

      const fixedTop = window.innerHeight - 80;
      const footerStopTop =
        document.getElementById('landing-footer-border')?.getBoundingClientRect().top ??
        Number.POSITIVE_INFINITY;
      const footerStopOffset = Number.isFinite(footerStopTop)
        ? footerStopTop - 94
        : Number.POSITIVE_INFINITY;
      const firstMilestoneCenter = milestones[0].center ?? fixedTop;
      let nextState: VisibleIndicatorState = 'locked';

      for (const milestone of milestones) {
        if ((milestone.center ?? Number.POSITIVE_INFINITY) <= fixedTop) {
          nextState = milestone.state;
        } else {
          break;
        }
      }

      const nextTop = Math.min(Math.max(firstMilestoneCenter, fixedTop), footerStopOffset);
      indicatorElement.style.top = `${Math.round(nextTop)}px`;

      if (nextState !== currentState) {
        currentState = nextState;
        setIndicatorState(nextState);
      }
    };

    const requestUpdate = () => {
      window.cancelAnimationFrame(animationFrame);
      animationFrame = window.requestAnimationFrame(updateState);
    };

    updateState();
    const scrollTarget = scrollContainer ?? window;

    scrollTarget.addEventListener('scroll', requestUpdate, { passive: true });
    window.addEventListener('resize', requestUpdate);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      scrollTarget.removeEventListener('scroll', requestUpdate);
      window.removeEventListener('resize', requestUpdate);
    };
  }, []);

  const visibleState: VisibleIndicatorState =
    indicatorState === 'hidden' ? 'locked' : indicatorState;
  const { icon, tone } = statusContent[visibleState];
  const label = t(visibleState);
  const accentClass = tone === 'focus' ? 'bg-focus' : 'bg-primary';

  return (
    <aside
      ref={indicatorRef}
      className={cn(
        'pointer-events-none fixed right-3 z-40 h-18 w-16 transition-[top] duration-150 ease-out sm:right-5 md:right-8 md:h-24 md:w-34',
        indicatorState === 'hidden' ? 'hidden' : 'block',
      )}
    >
      <Image
        src={icon}
        alt=""
        className="absolute right-0 top-0 size-11 -translate-y-1/2 object-contain md:size-15"
        aria-hidden="true"
      />
      <div className="absolute right-0 top-7 flex items-center justify-end gap-1.5 md:top-9 md:gap-2">
        <span className="hidden font-['Space_Grotesk','Manrope',sans-serif] text-[10px] uppercase leading-none tracking-[0.16em] text-white text-right sm:block">
          {label}
        </span>
        <span className={cn('hidden size-1.5 shrink-0 rounded-full sm:block', accentClass)} />
      </div>
    </aside>
  );
}
