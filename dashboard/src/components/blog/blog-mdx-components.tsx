import type { ComponentPropsWithoutRef } from 'react';
import Link from 'next/link';

const HEADING_FONT = "font-['Space_Grotesk','Manrope',sans-serif]";

function isExternal(href: string): boolean {
  return /^(https?:)?\/\//.test(href);
}

/** How each part of an article is drawn. Keeps every article looking the same. */
export const blogMdxComponents = {
  a: ({ href = '', children }: ComponentPropsWithoutRef<'a'>) =>
    isExternal(href) ? (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="text-focus hover:underline"
      >
        {children}
      </a>
    ) : (
      <Link href={href} className="text-focus hover:underline">
        {children}
      </Link>
    ),
  blockquote: (props: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote className="my-6 border-l-2 border-primary pl-4 text-white/80 italic" {...props} />
  ),
  code: (props: ComponentPropsWithoutRef<'code'>) => (
    <code
      className="rounded bg-surfaceChip px-1.5 py-0.5 font-mono text-[0.9em] text-white"
      {...props}
    />
  ),
  h2: (props: ComponentPropsWithoutRef<'h2'>) => (
    <h2
      className={`${HEADING_FONT} mt-10 mb-3 text-xl font-bold text-white sm:text-2xl`}
      {...props}
    />
  ),
  h3: (props: ComponentPropsWithoutRef<'h3'>) => (
    <h3
      className={`${HEADING_FONT} mt-8 mb-2 text-lg font-bold text-white sm:text-xl`}
      {...props}
    />
  ),
  hr: () => <hr className="my-10 border-borderGray" />,
  img: ({ alt = '', src, ...rest }: ComponentPropsWithoutRef<'img'>) => (
    // eslint-disable-next-line @next/next/no-img-element -- article images have unknown sizes
    <img
      alt={alt}
      src={src}
      className="my-6 h-auto max-w-full rounded-lg border border-borderGray"
      {...rest}
    />
  ),
  li: (props: ComponentPropsWithoutRef<'li'>) => <li className="pl-1" {...props} />,
  ol: (props: ComponentPropsWithoutRef<'ol'>) => (
    <ol className="my-4 list-decimal space-y-2 pl-6 marker:text-primary" {...props} />
  ),
  p: (props: ComponentPropsWithoutRef<'p'>) => <p className="my-4" {...props} />,
  pre: (props: ComponentPropsWithoutRef<'pre'>) => (
    <pre
      className="my-6 overflow-x-auto rounded-lg border border-borderGray bg-cardBg p-4 font-mono text-sm leading-6 text-white [&_code]:bg-transparent [&_code]:p-0"
      {...props}
    />
  ),
  table: (props: ComponentPropsWithoutRef<'table'>) => (
    <div className="my-6 overflow-x-auto rounded-lg border border-borderGray">
      <table className="w-full border-collapse text-left text-sm" {...props} />
    </div>
  ),
  td: (props: ComponentPropsWithoutRef<'td'>) => (
    <td className="border-t border-borderGray px-4 py-3 align-top" {...props} />
  ),
  th: (props: ComponentPropsWithoutRef<'th'>) => (
    <th className="bg-cardBg px-4 py-3 font-medium text-white" {...props} />
  ),
  ul: (props: ComponentPropsWithoutRef<'ul'>) => (
    <ul className="my-4 list-disc space-y-2 pl-6 marker:text-primary" {...props} />
  ),
};
