import { getFormatter, getTranslations } from 'next-intl/server';

import type { BlogPostSummary } from '@/lib/blog/posts';

type BlogPostMetaProps = {
  post: Pick<BlogPostSummary, 'author' | 'date' | 'minutesToRead'>;
};

/** The date, author and reading time line under an article's title. */
export async function BlogPostMeta({ post }: BlogPostMetaProps) {
  const t = await getTranslations('blog');
  const format = await getFormatter();

  return (
    <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-textGray">
      <time dateTime={post.date}>
        {format.dateTime(new Date(post.date), { dateStyle: 'long', timeZone: 'UTC' })}
      </time>
      <span aria-hidden="true">&bull;</span>
      <span>{t('by', { author: post.author })}</span>
      <span aria-hidden="true">&bull;</span>
      <span>{t('minutesToRead', { minutes: post.minutesToRead })}</span>
    </p>
  );
}
