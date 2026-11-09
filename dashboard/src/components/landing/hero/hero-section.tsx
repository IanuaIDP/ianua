import Image from 'next/image';
import Link from 'next/link';
import { useTranslations } from 'next-intl';

import heroBackground from '@/assets/hero-background.svg';
import purpleDoor from '@/assets/purple-door.svg';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { HERO_TECHNOLOGY_IDS, HERO_TRUST_POINT_IDS } from '@/constants/landing';

export function HeroSection() {
  const t = useTranslations('landing.hero');
  const tCommon = useTranslations('common');

  return (
    <section
      id="hero"
      className="relative isolate overflow-hidden bg-appBg px-6 pt-16 pb-10 sm:px-8 sm:pt-24 sm:pb-16 md:px-30 lg:min-h-180"
    >
      <Image
        src={heroBackground}
        alt=""
        className="pointer-events-none absolute left-1/2 top-14 h-104 w-[min(76rem,calc(100%-3rem))] max-w-none -translate-x-1/2 select-none object-cover"
        aria-hidden="true"
        priority
      />

      <div className="relative z-10 mx-auto flex w-full max-w-7xl flex-col items-start justify-between gap-10 lg:min-h-155 lg:flex-row lg:gap-12">
        <div className="flex w-full flex-col lg:w-[55%] lg:pb-25">
          <SectionBadge
            iconName="verified_user"
            className="border-white/10 bg-white/4.5 px-3.5 py-2 shadow-primary-soft backdrop-blur-md"
          >
            {t('badge')}
          </SectionBadge>

          <h1 className="mt-6 max-w-4xl font-['Space_Grotesk','Manrope',sans-serif] text-[38px] font-bold leading-11 text-white sm:mt-7 sm:text-5xl sm:leading-14 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => (
                <span className="text-primary brightness-125 drop-shadow-primary-text-glow">
                  {chunks}
                </span>
              ),
            })}
          </h1>

          <p className="mt-6 max-w-155 text-lg font-normal leading-7 text-white/58 sm:mt-8 sm:text-lg">
            {t('description')}
          </p>

          <div className="relative mt-8 flex w-full justify-center lg:hidden">
            <div className="relative w-fit py-2">
              <div className="relative z-10 h-[min(58vw,18rem)] w-[min(31vw,9.75rem)] min-h-52 min-w-28">
                <Image
                  src={purpleDoor}
                  alt={t('doorAlt')}
                  className="relative z-10 h-full w-full object-contain opacity-55 grayscale brightness-75"
                  priority
                />
                <div
                  className="pointer-events-none absolute inset-x-0 top-0 z-20 h-0 animate-door-reveal overflow-hidden"
                  aria-hidden="true"
                >
                  <Image
                    src={purpleDoor}
                    alt=""
                    className="h-[min(58vw,18rem)] min-h-52 w-[min(31vw,9.75rem)] min-w-28 object-contain drop-shadow-door-soft"
                  />
                </div>
                <span
                  className="pointer-events-none absolute left-0 top-0 z-30 h-0.75 w-full animate-door-scan-line bg-scanPurple"
                  aria-hidden="true"
                />
              </div>
            </div>
          </div>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row">
            <Link
              href="/sign-up"
              className="inline-flex h-10.5 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
            >
              {tCommon('startFree')}
            </Link>
            <Link
              href="#"
              className="inline-flex h-10.5 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {tCommon('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
          </div>

          <ul className="mt-8 mb-6 flex flex-wrap items-center justify-start gap-x-8 gap-y-4 text-center text-sm text-white sm:mt-12 sm:mb-8 2xl:mb-0">
            {HERO_TRUST_POINT_IDS.map((id) => (
              <li key={id} className="flex items-center justify-center gap-2 leading-none">
                <span
                  className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-primary"
                  aria-hidden="true"
                >
                  check_circle
                </span>
                <span className="mt-1">{t(`trustPoints.${id}`)}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="relative hidden w-full justify-center lg:flex lg:w-[45%]">
          <div className="relative w-fit py-2">
            <div className="relative z-10 h-135 w-73">
              <Image
                src={purpleDoor}
                alt={t('doorAlt')}
                className="relative z-10 h-full w-full object-contain opacity-55 grayscale brightness-75"
                priority
              />
              <div
                className="pointer-events-none absolute inset-x-0 top-0 z-20 h-0 animate-door-reveal overflow-hidden"
                aria-hidden="true"
              >
                <Image
                  src={purpleDoor}
                  alt=""
                  className="h-135 w-73 object-contain drop-shadow-door-soft"
                />
              </div>
              <span
                className="pointer-events-none absolute left-0 top-0 z-30 h-0.75 w-full animate-door-scan-line bg-scanPurple"
                aria-hidden="true"
              />
            </div>
            <div className="absolute bottom-30 -left-24 z-20 flex h-11.5 items-center gap-3 rounded-lg border border-borderGray bg-hero-chip-verified px-4 py-1.5 text-sm font-light text-primary">
              <span className="size-1.25 rounded-full bg-primary shadow-primary-glow" />
              {t('chipVerified')}
            </div>
            <div className="absolute top-35 -right-18 z-20 flex h-11.5 items-center gap-3 rounded-lg border border-transparent bg-hero-chip-denied-border bg-origin-border px-4 py-1.5 text-sm font-light text-error [background-clip:padding-box,border-box]">
              <span className="size-1.25 rounded-full bg-error shadow-error-glow" />
              {t('chipDenied')}
            </div>
          </div>
        </div>
      </div>
      <div className="relative z-10 -mx-6 border-y border-borderGray bg-appBg py-8 sm:-mx-8 sm:py-12 md:-mx-30">
        <ul className="mx-auto flex max-w-7xl flex-wrap items-center justify-center gap-x-6 gap-y-8 px-2 text-center text-sm font-bold text-textGray sm:gap-x-8 md:text-[21px] lg:gap-y-4 font-['Space_Grotesk','Manrope',sans-serif]">
          {HERO_TECHNOLOGY_IDS.map((id) => (
            <li key={id} className="hover:text-white">
              {t(`technologies.${id}`)}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
