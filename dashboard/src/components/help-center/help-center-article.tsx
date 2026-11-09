import Link from 'next/link';
import { getLocale, getTranslations } from 'next-intl/server';

import { HelpCenterFeedback } from '@/components/help-center/help-center-feedback';
import { DEFAULT_LOCALE, toAppLocale } from '@/i18n/config';
import type { HelpArticleRef, HelpContentBlock } from '@/types/help-center';
import { formatBackendDate } from '@/utils/date';
import {
  getAdjacentHelpArticleRefs,
  getHelpArticleHref,
  isHelpArticleWritten,
  localizeHelpArticleRef,
} from '@/utils/help-center';

function Block({ block }: { block: HelpContentBlock }) {
  if (block.type === 'paragraph') {
    return <p className="text-sm leading-6 text-textGray">{block.text}</p>;
  }

  if (block.type === 'list') {
    const ListTag = block.ordered ? 'ol' : 'ul';

    return (
      <ListTag
        className={
          block.ordered
            ? 'list-decimal space-y-2 pl-5 text-sm leading-6 text-textGray'
            : 'list-disc space-y-2 pl-5 text-sm leading-6 text-textGray'
        }
      >
        {block.items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ListTag>
    );
  }

  if (block.type === 'steps') {
    return (
      <ol className="flex flex-col gap-3">
        {block.items.map((item, index) => (
          <li key={item} className="flex items-center gap-3 text-sm leading-6 text-textGray">
            <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[11px] font-bold leading-none text-primary">
              {index + 1}
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ol>
    );
  }

  return (
    <div
      className={
        block.tone === 'warning'
          ? 'rounded-lg border border-orange/50 bg-orange/10 px-4 py-3 text-sm text-orange'
          : 'rounded-lg border border-borderGray bg-cardBg px-4 py-3 text-sm text-textGray'
      }
    >
      {block.text}
    </div>
  );
}

export async function HelpCenterArticle({ articleRef }: { articleRef: HelpArticleRef }) {
  const t = await getTranslations('helpCenter');
  const locale = await getLocale();
  const { article, category, slugPath } = articleRef;
  const adjacent = getAdjacentHelpArticleRefs(slugPath);
  const next = adjacent.next ? localizeHelpArticleRef(adjacent.next, locale) : undefined;
  const previous = adjacent.previous
    ? localizeHelpArticleRef(adjacent.previous, locale)
    : undefined;
  const written = isHelpArticleWritten(article);

  return (
    <article className="mx-auto w-full py-10">
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-primary">
        {category.title}
      </p>
      <h1 className="font-['Space_Grotesk','Manrope',sans-serif] text-4xl font-bold text-white">
        {article.title}
      </h1>

      {article.intro ? (
        <p className="mt-4 text-base leading-7 text-textGray">{article.intro}</p>
      ) : null}

      {written ? (
        <div className="mt-10 flex flex-col gap-10">
          {article.sections.map((section) => (
            <section key={section.id} id={section.id} className="scroll-mt-20">
              <h2 className="mb-3 font-['Space_Grotesk','Manrope',sans-serif] text-xl font-bold text-white">
                {section.heading}
              </h2>
              <div className="flex flex-col gap-3">
                {section.blocks.map((block, index) => (
                  <Block key={index} block={block} />
                ))}
              </div>
            </section>
          ))}
        </div>
      ) : (
        <div className="mt-10 rounded-lg border border-dashed border-borderGray px-5 py-8 text-center">
          <p className="text-sm font-medium text-white">{t('notWrittenTitle')}</p>
          <p className="mt-1 text-sm text-textGray">{t('notWrittenHint')}</p>
        </div>
      )}

      {article.lastUpdated ? (
        <p className="mt-10 text-xs text-textGray">
          {t('lastUpdated', {
            date: formatBackendDate(article.lastUpdated, toAppLocale(locale) ?? DEFAULT_LOCALE),
          })}
        </p>
      ) : null}

      <div className="mt-6 border-t border-borderGray pt-8">
        <HelpCenterFeedback />
      </div>

      {previous || next ? (
        <div className="mt-8 flex items-center justify-between gap-4 border-t border-borderGray pt-6">
          {previous ? (
            <Link
              href={getHelpArticleHref(previous.slugPath)}
              className="group flex flex-col items-start gap-1"
            >
              <span className="flex items-center gap-1 text-xs text-textGray">
                <span className="material-symbols-rounded text-sm!" aria-hidden="true">
                  arrow_back
                </span>
                {t('previous')}
              </span>
              <span className="text-sm font-medium text-white group-hover:text-primary">
                {previous.article.title}
              </span>
            </Link>
          ) : (
            <span />
          )}

          {next ? (
            <Link
              href={getHelpArticleHref(next.slugPath)}
              className="group flex flex-col items-end gap-1 text-right"
            >
              <span className="flex items-center gap-1 text-xs text-textGray">
                {t('next')}
                <span className="material-symbols-rounded text-sm!" aria-hidden="true">
                  arrow_forward
                </span>
              </span>
              <span className="text-sm font-medium text-white group-hover:text-primary">
                {next.article.title}
              </span>
            </Link>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
