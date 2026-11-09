import { notFound, redirect } from 'next/navigation';
import { getLocale } from 'next-intl/server';

import { HelpCenterArticle } from '@/components/help-center/help-center-article';
import { HelpCenterToc } from '@/components/help-center/help-center-toc';
import {
  getDefaultHelpArticleRef,
  getHelpArticleBySlugPath,
  getHelpArticleHref,
  localizeHelpArticleRef,
} from '@/utils/help-center';

const SCROLL_CONTAINER_ID = 'help-center-scroll-container';

type HelpCenterPageProps = {
  params: Promise<{ slug?: string[] }>;
};

export default async function HelpCenterPage({ params }: HelpCenterPageProps) {
  const { slug } = await params;

  if (!slug || slug.length === 0) {
    const defaultArticleRef = getDefaultHelpArticleRef();

    if (!defaultArticleRef) {
      notFound();
    }

    redirect(getHelpArticleHref(defaultArticleRef.slugPath));
  }

  const rawArticleRef = getHelpArticleBySlugPath(slug);

  if (!rawArticleRef) {
    notFound();
  }

  const articleRef = localizeHelpArticleRef(rawArticleRef, await getLocale());

  return (
    <>
      <main id={SCROLL_CONTAINER_ID} className="min-w-0 flex-1 overflow-y-auto px-12">
        <HelpCenterArticle articleRef={articleRef} />
      </main>

      <HelpCenterToc
        scrollContainerId={SCROLL_CONTAINER_ID}
        sections={articleRef.article.sections}
      />
    </>
  );
}
