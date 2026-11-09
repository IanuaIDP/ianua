import type { ReactNode } from 'react';
import Link from 'next/link';

import { LEGAL_CONTACT_EMAIL } from '@/constants/legal';
import { cn } from '@/utils/cn';

// The text of the legal pages is in messages/<language>.json under `legal`.
// These pieces only carry the markup, so both pages look the same.

const BODY_CLASS = 'text-sm leading-6 text-textGray sm:text-base sm:leading-7';

export const legalLinkClassName = 'text-focus hover:underline';

/** Tags used inside legal messages, for `t.rich`. */
export const legalRichTags = {
  brand: (chunks: ReactNode) => <span className="text-primary">{chunks}</span>,
  highlight: (chunks: ReactNode) => <span className="text-primary">{chunks}</span>,
  mail: (chunks: ReactNode) => (
    <Link href={`mailto:${LEGAL_CONTACT_EMAIL}`} className={legalLinkClassName}>
      {chunks}
    </Link>
  ),
  privacy: (chunks: ReactNode) => (
    <Link
      href="/privacy-policy"
      target="_blank"
      rel="noopener noreferrer"
      className={legalLinkClassName}
    >
      {chunks}
    </Link>
  ),
};

export function LegalSection({ children, title }: { children: ReactNode; title: ReactNode }) {
  return (
    <section>
      <h2 className="font-['Space_Grotesk','Manrope',sans-serif] text-xl font-bold text-white sm:text-2xl">
        {title}
      </h2>
      {children}
    </section>
  );
}

export function LegalParagraph({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <p className={cn('mt-4', BODY_CLASS, className)}>{children}</p>;
}

/** Several paragraphs, spaced. */
export function LegalProse({ children }: { children: ReactNode }) {
  return <div className={cn('mt-4 space-y-4', BODY_CLASS)}>{children}</div>;
}

export function LegalList({ children }: { children: ReactNode }) {
  return <ul className={cn('mt-4 space-y-2', BODY_CLASS)}>{children}</ul>;
}

export function LegalBullet({ children }: { children: ReactNode }) {
  return (
    <li className="flex gap-2 pl-1">
      <span className="text-primary" aria-hidden="true">
        &bull;
      </span>
      <span>{children}</span>
    </li>
  );
}
