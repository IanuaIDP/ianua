'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { FAQ_ITEM_IDS } from '@/constants/landing';
import { cn } from '@/utils/cn';

const midpoint = Math.ceil(FAQ_ITEM_IDS.length / 2);
const leftColumnItems = FAQ_ITEM_IDS.slice(0, midpoint).map((id, index) => ({ id, index }));
const rightColumnItems = FAQ_ITEM_IDS.slice(midpoint).map((id, index) => ({
  id,
  index: index + midpoint,
}));

export function FaqSection() {
  const t = useTranslations('landing.faq');
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  function renderFaqCard({ id, index }: { id: (typeof FAQ_ITEM_IDS)[number]; index: number }) {
    const isOpen = openIndex === index;

    return (
      <div
        key={id}
        className="overflow-hidden rounded-lg border border-borderGray transition-colors duration-200 hover:bg-hoverBg"
      >
        <button
          type="button"
          className={cn(
            'flex w-full items-start justify-between gap-4 px-4 pt-3.5 text-left sm:gap-6',
            isOpen ? 'pb-2' : 'pb-3.5',
          )}
          onClick={() => setOpenIndex(isOpen ? null : index)}
          aria-expanded={isOpen}
        >
          <span className="min-w-0 font-bold font-['Space_Grotesk','Manrope',sans-serif] text-white text-base">
            {t(`items.${id}.question`)}
          </span>
          <span
            className={cn(
              'flex size-7 shrink-0 items-center justify-center text-[28px] leading-none transition-transform duration-300 ease-out',
              isOpen ? 'rotate-90 text-textGray' : 'rotate-0 text-primary',
            )}
            aria-hidden="true"
          >
            {isOpen ? '×' : '+'}
          </span>
        </button>

        <div
          className={cn(
            'grid transition-[grid-template-rows,opacity] duration-300 ease-out',
            isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
          )}
          aria-hidden={!isOpen}
        >
          <div className="min-h-0 overflow-hidden">
            <p className="px-4 pb-4 text-sm text-textGray">{t(`items.${id}.answer`)}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <section id="faq" className="bg-appBg px-6 py-12 sm:py-16 lg:py-24">
      <div className="mx-auto flex max-w-7xl flex-col items-center text-center">
        <ScrollReveal className="flex flex-col items-center">
          <SectionBadge
            className="mx-auto border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="mt-6 max-w-4xl font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>
        </ScrollReveal>

        <ScrollReveal className="mt-10 w-full min-w-0 text-left sm:mt-12" delayMs={140}>
          <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-3">{leftColumnItems.map(renderFaqCard)}</div>
            <div className="flex flex-col gap-3">{rightColumnItems.map(renderFaqCard)}</div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
