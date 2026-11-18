import type { Metadata } from 'next';
import { getLocale, getTranslations } from 'next-intl/server';

import { BlogPostCard } from '@/components/blog/blog-post-card';
import { blogPosts } from '@/lib/blog/posts';
import { toAppLocale } from '@/i18n/config';

export const dynamic = 'force-dynamic';

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations('blog.meta');

  return { description: t('description'), title: t('title') };
}

export default async function BlogPage() {
  const t = await getTranslations('blog');
  const locale = toAppLocale(await getLocale()) ?? 'en';
  const posts = await blogPosts(locale);

  return (
    <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 sm:py-20">
      <h1 className="font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-tight text-white sm:text-4xl">
        {t('heading')}
      </h1>
      <p className="mt-4 max-w-3xl text-sm leading-6 text-textGray sm:text-base sm:leading-7">
        {t('subtitle')}
      </p>

      {posts.length === 0 ? (
        <p className="mt-12 rounded-lg border border-borderGray bg-cardBg px-4 py-6 text-center text-sm text-textGray">
          {t('empty')}
        </p>
      ) : (
        <div className="mt-10 grid gap-4 sm:mt-12 sm:gap-6 md:grid-cols-2">
          {posts.map((post) => (
            <BlogPostCard key={post.slug} post={post} />
          ))}
        </div>
      )}
    </div>
  );
}
