import Link from 'next/link';
import { getTranslations } from 'next-intl/server';

import { BlogPostMeta } from '@/components/blog/blog-post-meta';
import type { BlogPostSummary } from '@/lib/blog/posts';

type BlogPostCardProps = {
  post: BlogPostSummary;
};

export async function BlogPostCard({ post }: BlogPostCardProps) {
  const t = await getTranslations('blog');

  return (
    <article className="relative flex h-full flex-col rounded-xl border border-borderGray bg-cardBg p-5 transition-colors duration-200 hover:bg-hoverBg sm:p-6">
      <BlogPostMeta post={post} />
      <h2 className="mt-3 font-['Space_Grotesk','Manrope',sans-serif] text-lg font-bold leading-snug text-white sm:text-xl">
        <Link href={`/blog/${post.slug}`} className="after:absolute after:inset-0">
          {post.title}
        </Link>
      </h2>
      <p className="mt-2 text-sm leading-6 text-textGray sm:text-base sm:leading-7">
        {post.description}
      </p>
      {post.tags.length > 0 ? (
        <ul className="mt-auto flex flex-wrap gap-2 pt-4" aria-label={t('tagsAriaLabel')}>
          {post.tags.map((tag) => (
            <li
              key={tag}
              className="rounded-full border border-borderGray bg-surfaceChip px-3 py-1 text-xs text-white/70"
            >
              {tag}
            </li>
          ))}
        </ul>
      ) : null}
    </article>
  );
}
