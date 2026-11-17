import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { MDXRemote } from 'next-mdx-remote/rsc';
import { getLocale, getTranslations } from 'next-intl/server';

import { blogMdxComponents } from '@/components/blog/blog-mdx-components';
import { BlogPostMeta } from '@/components/blog/blog-post-meta';
import { toAppLocale } from '@/i18n/config';
import { blogPost } from '@/lib/blog/posts';

export const dynamic = 'force-dynamic';

type BlogPostPageProps = {
  params: Promise<{ slug: string }>;
};

async function currentPost(params: BlogPostPageProps['params']) {
  const { slug } = await params;
  const locale = toAppLocale(await getLocale()) ?? 'en';

  return blogPost(slug, locale);
}

export async function generateMetadata({ params }: BlogPostPageProps): Promise<Metadata> {
  const post = await currentPost(params);

  if (!post) {
    return {};
  }

  return { description: post.description, title: post.title };
}

export default async function BlogPostPage({ params }: BlogPostPageProps) {
  const post = await currentPost(params);

  if (!post) {
    notFound();
  }

  const t = await getTranslations('blog');

  return (
    <article className="mx-auto max-w-3xl px-4 py-12 sm:px-6 sm:py-20">
      <Link
        href="/blog"
        className="inline-flex items-center gap-1 text-sm text-textGray transition-colors duration-200 hover:text-primary"
      >
        <span className="material-symbols-rounded" aria-hidden="true">
          arrow_back
        </span>
        {t('back')}
      </Link>

      <h1 className="mt-6 font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-tight text-white sm:text-4xl">
        {post.title}
      </h1>
      <div className="mt-4">
        <BlogPostMeta post={post} />
      </div>
      {post.isTranslated ? null : (
        <p className="mt-4 rounded-lg border border-borderGray bg-cardBg px-4 py-3 text-sm text-textGray">
          {t('englishOnly')}
        </p>
      )}

      <div className="mt-8 text-sm leading-6 text-textGray [overflow-wrap:anywhere] sm:text-base sm:leading-7">
        <MDXRemote source={post.body} components={blogMdxComponents} />
      </div>
    </article>
  );
}
